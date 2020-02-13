# workaround the syntax error from: import fdroidserver.import

import inspect
import os
import sys

localmodule = os.path.realpath(
    os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), '..'))
print('localmodule: ' + localmodule)
if localmodule not in sys.path:
    sys.path.insert(0, localmodule)

class Options:
    def __init__(self):
        self.rev = None
        self.subdir = None

module = __import__('fdroidserver.import')
for name, obj in inspect.getmembers(module):
    if name == 'import':
        clone_to_tmp_dir = obj.clone_to_tmp_dir
        get_all_gradle_and_manifests = obj.get_all_gradle_and_manifests
        get_app_from_url = obj.get_app_from_url
        get_gradle_subdir = obj.get_gradle_subdir
        obj.options = Options()
        options = obj.options
        break

globals().update(vars(module))
