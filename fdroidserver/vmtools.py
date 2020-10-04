#!/usr/bin/env python3
#
# vmtools.py - part of the FDroid server tools
# Copyright (C) 2017 Michael Poehn <michael.poehn@fsfe.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from os.path import isdir, isfile, basename, abspath, expanduser
import os
import math
import json
import tarfile
import shutil
import subprocess
import textwrap
import logging
import threading

from hashlib import md5
from pathlib import Path

from .common import FDroidException

from fdroidserver import _

lock = threading.Lock()

VM_CACHE_LOCATION = '/vagrant/cache'


def write_vagrantfile(vagrantfile, cachedir, share_type):
    with open(vagrantfile, 'w') as f:
        if share_type == 'virtualbox':
            from invoke import run, UnexpectedExit
            # All of this is a workaround for virtualbox not supporting read-only shared folders
            # ro share in virtbualbox means root inside the VM has still write access, which isn't good enough for us
            # So we create a ro bind mount of the cache folder and share that inside the VM instead
            ro_cachedir = os.path.join(cachedir, 'buildserver')
            os.makedirs(ro_cachedir, exist_ok=True)
            # Test if we are mounted ro already
            if os.path.isfile(os.path.join(cachedir, 'MOUNT_TEST')):
                os.remove(os.path.join(cachedir, 'MOUNT_TEST'))
            Path(os.path.join(cachedir, 'MOUNT_TEST')).touch()
            if os.path.isfile(os.path.join(ro_cachedir, 'MOUNT_TEST')):
                try:
                    os.remove(os.path.join(ro_cachedir, 'MOUNT_TEST'))
                    logging.error("Cachedir is bind mounted to {0} but still writable. Aborting!".format(ro_cachedir))
                except OSError:
                    # Read-only filesystem expected, all good.
                    # Cleanup the original file.
                    os.remove(os.path.join(cachedir, 'MOUNT_TEST'))
                    pass
            else:
                cmd = "mount --bind -o ro {0} {1}"
                try:
                    run(cmd.format(cachedir, ro_cachedir))
                except UnexpectedExit:
                    logging.warning("Need sudo access for mounting cache read-only for virtualbox")
                    logging.warning("Add the following to /etc/fstab to prevent that:\n\t {0} {1} none bind,ro".format(cachedir, ro_cachedir))
                    cmd = "sudo " + cmd
                    run(cmd.format(cachedir, ro_cachedir))
            cachedir = ro_cachedir

        # libvirt cannot create snapshots with a mounted shared folder, so we disable auto-mounting
        # and manually mount it befor each build
        # virtulabox vms on the other hand seem to ignore the automount flag, so we let
        if share_type == 'virtualbox':
            automount = 'true'
        else:
            automount = 'false'
        f.write(textwrap.dedent("""\
            # generated file, do not change.

            Vagrant.configure("2") do |config|
                config.vm.box = "buildserver"
                config.vm.synced_folder ".", "/vagrant", disabled: true
                config.vm.synced_folder "{0}", '/vagrant/cache', create: true, mount: {1}, readonly: true, type: "{2}"
            end
            """.format(cachedir, automount, share_type)))


def get_clean_builder(serverdir, cachedir, reset=False):
    if not os.path.isdir(serverdir):
        if os.path.islink(serverdir):
            os.unlink(serverdir)
        logging.info("buildserver path does not exists, creating %s", serverdir)
        os.makedirs(serverdir)
    provider = get_vagrant_provider(serverdir)
    vagrantfile = os.path.join(serverdir, 'Vagrantfile')
    if provider == 'libvirt':
        share_type = '9p'
    else:
        share_type = 'virtualbox'
    write_vagrantfile(vagrantfile, cachedir, share_type)

    vm = get_build_vm(serverdir)
    if reset:
        logging.info('resetting buildserver by request')
    elif not vm.vagrant_uuid_okay():
        logging.info('resetting buildserver, because vagrant vm is not okay.')
        reset = True
    elif not vm.snapshot_exists('fdroidclean'):
        logging.info("resetting buildserver, because snapshot 'fdroidclean' is not present.")
        reset = True

    if reset:
        vm.destroy()
    vm.up()
    vm.suspend()

    if reset:
        logging.info('buildserver recreated: taking a clean snapshot')
        vm.snapshot_create('fdroidclean')
    else:
        logging.info('builserver ok: reverting to clean snapshot')
        vm.snapshot_revert('fdroidclean')
    vm.up()

    try:
        sshinfo = vm.sshinfo()
    except FDroidBuildVmException:
        # workaround because libvirt sometimes likes to forget
        # about ssh connection info even though the vm is running
        vm.halt()
        vm.up()
        sshinfo = vm.sshinfo()

    vm.mount_cachedir(cachedir)

    return sshinfo


def _check_call(cmd, cwd=None):
    logging.debug(' '.join(cmd))
    return subprocess.check_call(cmd, shell=False, cwd=cwd)


def _check_output(cmd, cwd=None):
    logging.debug(' '.join(cmd))
    return subprocess.check_output(cmd, shell=False, cwd=cwd)


def get_vagrant_provider(srvdir):
    """Try guessing the vagrant provider from various system characteristics"""
    abssrvdir = abspath(srvdir)

    # try guessing provider from installed software
    kvm_installed = shutil.which('kvm') is not None
    kvm_installed |= shutil.which('qemu') is not None
    kvm_installed |= shutil.which('qemu-kvm') is not None
    kvm_installed |= shutil.which('qemu-system-x86_64') is not None
    vbox_installed = shutil.which('VBoxHeadless') is not None
    if kvm_installed and vbox_installed:
        logging.debug('both kvm and vbox are installed.')
    elif kvm_installed:
        logging.debug('libvirt is the sole installed and supported vagrant provider, selecting \'libvirt\'')
        return 'libvrt'
    elif vbox_installed:
        logging.debug('virtualbox is the sole installed and supported vagrant provider, selecting \'virtualbox\'')
        return 'virtualbox'
    else:
        logging.debug('could not confirm that either virtualbox or kvm/libvirt are installed')

    # try guessing provider from .../srvdir/.vagrant internals
    vagrant_libvirt_path = os.path.join(abssrvdir, '.vagrant', 'machines',
                                        'default', 'libvirt')
    has_libvirt_machine = isdir(vagrant_libvirt_path) and len(os.listdir(vagrant_libvirt_path)) > 0
    vagrant_virtualbox_path = os.path.join(abssrvdir, '.vagrant', 'machines',
                                           'default', 'virtualbox')
    has_vbox_machine = isdir(vagrant_virtualbox_path) and len(os.listdir(vagrant_virtualbox_path)) > 0
    if has_libvirt_machine and has_vbox_machine:
        logging.info('build vm provider lookup found virtualbox and libvirt, defaulting to \'virtualbox\'')
        return 'virtualbox'
    elif has_libvirt_machine:
        logging.debug('build vm provider lookup found \'libvirt\'')
        return 'libvirt'
    elif has_vbox_machine:
        logging.debug('build vm provider lookup found \'virtualbox\'')
        return 'virtualbox'

    # try guessing provider from available buildserver boxes
    available_boxes = []
    import vagrant
    boxes = vagrant.Vagrant().box_list()
    for box in boxes:
        if box.name == "buildserver":
            available_boxes.append(box.provider)
    if "libvirt" in available_boxes and "virtualbox" in available_boxes:
        logging.info('basebox lookup found virtualbox and libvirt boxes, defaulting to \'virtualbox\'')
        return 'virtualbox'
    elif "libvirt" in available_boxes:
        logging.info('\'libvirt\' buildserver box available, using that')
        return 'libvirt'
    elif "virtualbox" in available_boxes:
        logging.info('\'virtualbox\' buildserver box available, using that')
        return 'virtualbox'
    else:
        logging.debug('No available \'buildserver\' box.')
        return None


def get_build_vm(srvdir, provider=None):
    """Factory function for getting FDroidBuildVm instances.

    This function tries to figure out what hypervisor should be used
    and creates an object for controlling a build VM.

    :param srvdir: path to a directory which contains a Vagrantfile
    :param provider: optionally this parameter allows specifying an
        specific vagrant provider.
    :returns: FDroidBuildVm instance.
    """
    abssrvdir = abspath(srvdir)

    # use supplied provider
    if not provider:
        provider = get_vagrant_provider(srvdir)
    if not provider:
        logging.error('Cannot determine vm provider. Exiting...')
        os._exit(1)
    if provider == 'libvirt':
        logging.debug('build vm provider \'libvirt\' selected')
        return LibvirtBuildVm(abssrvdir)
    elif provider == 'virtualbox':
        logging.debug('build vm provider \'virtualbox\' selected')
        return VirtualboxBuildVm(abssrvdir)
    else:
        logging.warning('build vm provider not supported: \'%s\'', provider)


class FDroidBuildVmException(FDroidException):
    pass


class FDroidBuildVm():
    """Abstract base class for working with FDroids build-servers.

    Use the factory method `fdroidserver.vmtools.get_build_vm()` for
    getting correct instances of this class.

    This is intended to be a hypervisor independent, fault tolerant
    wrapper around the vagrant functions we use.
    """
    def __init__(self, srvdir):
        """Create new server class.
        """
        self.srvdir = srvdir
        self.srvname = basename(srvdir) + '_default'
        self.vgrntfile = os.path.join(srvdir, 'Vagrantfile')
        self.srvuuid = self._vagrant_fetch_uuid()
        if not isdir(srvdir):
            raise FDroidBuildVmException("Can not init vagrant, directory %s not present" % (srvdir))
        if not isfile(self.vgrntfile):
            raise FDroidBuildVmException("Can not init vagrant, '%s' not present" % (self.vgrntfile))
        import vagrant
        self.vgrnt = vagrant.Vagrant(root=srvdir, out_cm=vagrant.stdout_cm, err_cm=vagrant.stdout_cm)

    def up(self, provision=True):
        global lock
        with lock:
            try:
                self.vgrnt.up(provision=provision, provider=self.provider)
                self.srvuuid = self._vagrant_fetch_uuid()
            except subprocess.CalledProcessError as e:
                raise FDroidBuildVmException("could not bring up vm '%s'" % self.srvname) from e

    def suspend(self):
        global lock
        with lock:
            logging.info('suspending buildserver')
            try:
                self.vgrnt.suspend()
            except subprocess.CalledProcessError as e:
                raise FDroidBuildVmException("could not suspend vm '%s'" % self.srvname) from e

    def halt(self):
        global lock
        with lock:
            self.vgrnt.halt(force=True)

    def destroy(self):
        """Remove every trace of this VM from the system.

        This includes deleting:
        * hypervisor specific definitions
        * vagrant state informations (eg. `.vagrant` folder)
        * images related to this vm
        """
        logging.info("destroying vm '%s'", self.srvname)
        try:
            self.vgrnt.destroy()
            logging.debug('vagrant destroy completed')
        except subprocess.CalledProcessError as e:
            logging.exception('vagrant destroy failed: %s', e)
        vgrntdir = os.path.join(self.srvdir, '.vagrant')
        try:
            shutil.rmtree(vgrntdir)
            logging.debug('deleted vagrant dir: %s', vgrntdir)
        except Exception as e:
            logging.debug("could not delete vagrant dir: %s, %s", vgrntdir, e)
        try:
            _check_call(['vagrant', 'global-status', '--prune'])
        except subprocess.CalledProcessError as e:
            logging.debug('pruning global vagrant status failed: %s', e)

    def package(self, output=None):
        self.vgrnt.package(output=output)

    def vagrant_uuid_okay(self):
        '''Having an uuid means that vagrant up has run successfully.'''
        if self.srvuuid is None:
            return False
        return True

    def _vagrant_file_name(self, name):
        return name.replace('/', '-VAGRANTSLASH-')

    def _vagrant_fetch_uuid(self):
        if isfile(os.path.join(self.srvdir, '.vagrant')):
            # Vagrant 1.0 - it's a json file...
            with open(os.path.join(self.srvdir, '.vagrant')) as f:
                id = json.load(f)['active']['default']
                logging.debug('vm uuid: %s', id)
            return id
        elif isfile(os.path.join(self.srvdir, '.vagrant', 'machines',
                                 'default', self.provider, 'id')):
            # Vagrant 1.2 (and maybe 1.1?) it's a directory tree...
            with open(os.path.join(self.srvdir, '.vagrant', 'machines',
                                   'default', self.provider, 'id')) as f:
                id = f.read()
                logging.debug('vm uuid: %s', id)
            return id
        else:
            logging.debug('vm uuid is None')
            return None

    def box_add(self, boxname, boxfile, force=True):
        """Add vagrant box to vagrant.

        :param boxname: name assigned to local deployment of box
        :param boxfile: path to box file
        :param force: overwrite existing box image (default: True)
        """
        boxfile = abspath(boxfile)
        if not isfile(boxfile):
            raise FDroidBuildVmException('supplied boxfile \'%s\' does not exist', boxfile)
        self.vgrnt.box_add(boxname, abspath(boxfile), force=force)

    def box_remove(self, boxname):
        try:
            _check_call(['vagrant', 'box', 'remove', '--all', '--force', boxname])
        except subprocess.CalledProcessError as e:
            logging.debug('tried removing box %s, but is did not exist: %s', boxname, e)
        boxpath = os.path.join(expanduser('~'), '.vagrant',
                               self._vagrant_file_name(boxname))
        if isdir(boxpath):
            logging.info("attempting to remove box '%s' by deleting: %s",
                         boxname, boxpath)
            shutil.rmtree(boxpath)

    def sshinfo(self):
        """Get ssh connection info for a vagrant VM

        :returns: A dictionary containing 'hostname', 'port', 'user'
            and 'idfile'
        """
        import paramiko
        try:
            sshconfig_path = os.path.join(self.srvdir, 'sshconfig')
            with open(sshconfig_path, 'wb') as fp:
                fp.write(_check_output(['vagrant', 'ssh-config'],
                                       cwd=self.srvdir))
            vagranthost = 'default'  # Host in ssh config file
            sshconfig = paramiko.SSHConfig()
            with open(sshconfig_path, 'r') as f:
                sshconfig.parse(f)
            sshconfig = sshconfig.lookup(vagranthost)
            idfile = sshconfig['identityfile']
            if isinstance(idfile, list):
                idfile = idfile[0]
            elif idfile.startswith('"') and idfile.endswith('"'):
                idfile = idfile[1:-1]
            return {'hostname': sshconfig['hostname'],
                    'port': int(sshconfig['port']),
                    'user': sshconfig['user'],
                    'idfile': idfile}
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("Error getting ssh config") from e

    def mount_cachedir(self, cachedir):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_create(self, snapshot_name):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_list(self):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_exists(self, snapshot_name):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_revert(self, snapshot_name):
        raise NotImplementedError('not implemented, please use a sub-type instance')


class LibvirtBuildVm(FDroidBuildVm):
    def __init__(self, srvdir):
        self.provider = 'libvirt'
        super().__init__(srvdir)
        import libvirt

        try:
            self.conn = libvirt.open('qemu:///system')
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not connect to libvirtd: %s' % (e))

    def destroy(self):

        super().destroy()

        # resorting to virsh instead of libvirt python bindings, because
        # this is way more easy and therefore fault tolerant.
        # (eg. lookupByName only works on running VMs)
        try:
            _check_call(('virsh', '-c', 'qemu:///system', 'destroy', self.srvname))
        except subprocess.CalledProcessError as e:
            logging.info("could not force libvirt domain '%s' off: %s", self.srvname, e)
        try:
            # libvirt python bindings do not support all flags required
            # for undefining domains correctly.
            _check_call(('virsh', '-c', 'qemu:///system', 'undefine', self.srvname, '--nvram', '--managed-save', '--remove-all-storage', '--snapshots-metadata'))
        except subprocess.CalledProcessError as e:
            logging.info("could not undefine libvirt domain '%s': %s", self.srvname, e)

    def package(self, output=None, keep_box_file=False):
        if not output:
            output = "buildserver.box"
            logging.debug("no output name set for packaging '%s', "
                          "defaulting to %s", self.srvname, output)
        storagePool = self.conn.storagePoolLookupByName('default')
        domainInfo = self.conn.lookupByName(self.srvname).info()
        if storagePool:

            if isfile('metadata.json'):
                os.remove('metadata.json')
            if isfile('Vagrantfile'):
                os.remove('Vagrantfile')
            if isfile('box.img'):
                os.remove('box.img')

            logging.debug('preparing box.img for box %s', output)
            vol = storagePool.storageVolLookupByName(self.srvname + '.img')
            imagepath = vol.path()
            # TODO use a libvirt storage pool to ensure the img file is readable
            if not os.access(imagepath, os.R_OK):
                logging.warning(_('Cannot read "{path}"!').format(path=imagepath))
                _check_call(['sudo', '/bin/chmod', '-R', 'a+rX', '/var/lib/libvirt/images'])
            shutil.copy2(imagepath, 'box.img')
            _check_call(['qemu-img', 'rebase', '-p', '-b', '', 'box.img'])
            img_info_raw = _check_output(['qemu-img', 'info', '--output=json', 'box.img'])
            img_info = json.loads(img_info_raw.decode('utf-8'))
            metadata = {"provider": "libvirt",
                        "format": img_info['format'],
                        "virtual_size": math.ceil(img_info['virtual-size'] / (1024. ** 3)),
                        }

            logging.debug('preparing metadata.json for box %s', output)
            with open('metadata.json', 'w') as fp:
                fp.write(json.dumps(metadata))
            logging.debug('preparing Vagrantfile for box %s', output)
            vagrantfile = textwrap.dedent("""\
                  Vagrant.configure("2") do |config|
                    config.ssh.username = "vagrant"
                    config.ssh.password = "vagrant"

                    config.vm.provider :libvirt do |libvirt|

                      libvirt.driver = "kvm"
                      libvirt.host = ""
                      libvirt.connect_via_ssh = false
                      libvirt.storage_pool_name = "default"
                      libvirt.cpus = {cpus}
                      libvirt.memory = {memory}

                    end
                  end""".format_map({'memory': str(int(domainInfo[1] / 1024)), 'cpus': str(domainInfo[3])}))
            with open('Vagrantfile', 'w') as fp:
                fp.write(vagrantfile)
            try:
                import libarchive
                with libarchive.file_writer(output, 'gnutar', 'gzip') as tar:
                    logging.debug('adding files to box %s ...', output)
                    tar.add_files('metadata.json', 'Vagrantfile', 'box.img')
            except (ImportError, AttributeError):
                with tarfile.open(output, 'w:gz') as tar:
                    logging.debug('adding metadata.json to box %s ...', output)
                    tar.add('metadata.json')
                    logging.debug('adding Vagrantfile to box %s ...', output)
                    tar.add('Vagrantfile')
                    logging.debug('adding box.img to box %s ...', output)
                    tar.add('box.img')

            if not keep_box_file:
                logging.debug('box packaging complete, removing temporary files.')
                os.remove('metadata.json')
                os.remove('Vagrantfile')
                os.remove('box.img')

        else:
            logging.warning("could not connect to storage-pool 'default', "
                            "skip packaging buildserver box")

    def box_add(self, boxname, boxfile, force=True):
        boximg = '%s_vagrant_box_image_0.img' % (boxname)
        if force:
            try:
                _check_call(['virsh', '-c', 'qemu:///system', 'vol-delete', '--pool', 'default', boximg])
                logging.debug("removed old box image '%s'"
                              "from libvirt storeage pool", boximg)
            except subprocess.CalledProcessError as e:
                logging.debug("tried removing old box image '%s',"
                              "file was not present in first place",
                              boximg, exc_info=e)
        super().box_add(boxname, boxfile, force)

    def box_remove(self, boxname):
        super().box_remove(boxname)
        try:
            _check_call(['virsh', '-c', 'qemu:///system', 'vol-delete', '--pool', 'default', '%s_vagrant_box_image_0.img' % (boxname)])
        except subprocess.CalledProcessError as e:
            logging.debug("tried removing '%s', file was not present in first place", boxname, exc_info=e)

    def mount_cachedir(self, cachedir):
        from fabric import Connection
        ssh = self.sshinfo()
        con = Connection(ssh['hostname'], user=ssh['user'], port=ssh['port'],
                         connect_kwargs={"key_filename": ssh['idfile']})
        con.sudo('mkdir -p ' + VM_CACHE_LOCATION)
        # See https://github.com/vagrant-libvirt/vagrant-libvirt/blob/e7cb0fe00f16b82e866a11162fa5cbf46998d520/lib/vagrant-libvirt/cap/synced_folder.rb#L44
        mount_tag = md5(cachedir.encode('UTF-8')).hexdigest()[:31]  # nosec this is how vagrant-libvirt calculates the folder mount_tag
        mount_cmd = 'mount -t 9p -o trans=virtio,version=9p2000.L {0} {1}'
        con.sudo(mount_cmd.format(mount_tag, VM_CACHE_LOCATION))

    def snapshot_create(self, snapshot_name):
        logging.info("creating snapshot '%s' for vm '%s'", snapshot_name, self.srvname)
        try:
            _check_call(['virsh', '-c', 'qemu:///system', 'snapshot-create-as', self.srvname, snapshot_name])
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not create snapshot '%s' "
                                         "of libvirt vm '%s'"
                                         % (snapshot_name, self.srvname)) from e

    def snapshot_list(self):
        import libvirt
        try:
            dom = self.conn.lookupByName(self.srvname)
            return dom.listAllSnapshots()
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not list snapshots for domain \'%s\'' % self.srvname) from e

    def snapshot_exists(self, snapshot_name):
        import libvirt
        try:
            dom = self.conn.lookupByName(self.srvname)
            return dom.snapshotLookupByName(snapshot_name) is not None
        except libvirt.libvirtError:
            return False

    def snapshot_revert(self, snapshot_name):
        logging.info("reverting vm '%s' to snapshot '%s'", self.srvname, snapshot_name)
        import libvirt
        try:
            dom = self.conn.lookupByName(self.srvname)
            snap = dom.snapshotLookupByName(snapshot_name)
            dom.revertToSnapshot(snap)
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not revert domain \'%s\' to snapshot \'%s\''
                                         % (self.srvname, snapshot_name)) from e


class VirtualboxBuildVm(FDroidBuildVm):

    def __init__(self, srvdir):
        self.provider = 'virtualbox'
        super().__init__(srvdir)

    def snapshot_create(self, snapshot_name):
        logging.info("creating snapshot '%s' for vm '%s'", snapshot_name, self.srvname)
        try:
            _check_call(['VBoxManage', 'snapshot', self.srvuuid, 'take', 'fdroidclean'], cwd=self.srvdir)
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException('could not cerate snapshot '
                                         'of virtualbox vm %s'
                                         % self.srvname) from e

    def snapshot_list(self):
        try:
            o = _check_output(['VBoxManage', 'snapshot',
                               self.srvuuid, 'list',
                               '--details'], cwd=self.srvdir)
            return o
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not list snapshots "
                                         "of virtualbox vm '%s'"
                                         % (self.srvname)) from e

    def snapshot_exists(self, snapshot_name):
        try:
            return str(snapshot_name) in str(self.snapshot_list())
        except FDroidBuildVmException:
            return False

    def snapshot_revert(self, snapshot_name):
        logging.info("reverting vm '%s' to snapshot '%s'",
                     self.srvname, snapshot_name)
        try:
            _check_call(['VBoxManage', 'snapshot', self.srvuuid,
                         'restore', 'fdroidclean'], cwd=self.srvdir)
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not load snapshot "
                                         "'fdroidclean' for vm '%s'"
                                         % (self.srvname)) from e

    def mount_cachedir(self, cachedir):
        # vagrant virtualbox always mounts the cachedir when bringing up the VM, so no need to do it here
        pass
