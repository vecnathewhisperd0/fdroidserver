import math
import xml.etree.ElementTree as XMLElementTree  # nosec

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.axml import ARSCResTableConfig, AXMLPrinter
from cairosvg import svg2png

XMLNS_ANDROID = '{http://schemas.android.com/apk/res/android}'

apkobject = APK(apkfile)
default_config = ARSCResTableConfig.default_config()
screen_resolutions = {
    'xxxhdpi': '640',
    'xxhdpi': '480',
    'xhdpi': '320',
    'hdpi': '240',
    'mdpi': '160',
    'ldpi': '120',
    'tvdpi': '213',
    'undefineddpi': '-1',
    'anydpi': '65534',
    'nodpi': '65535',
}


def icon_extractor(apkobject):
    arsc = apkobject.get_android_resources()
    icon_id_str = apkobject.get_element('application', 'icon')
    if not icon_id_str:
        return
    icon_id = arsc.parse_id(icon_id_str)[0]
    icon_res = arsc.get_resolved_res_configs(icon_id)
    print(icon_res)
    icons_src = {}
    has_png = False
    for config, path in icon_res:
        if path.endswith('.png'):
            has_png = True
        print(config.get_density())
        qualifier = config.get_qualifier()
        if not qualifier:
            continue
        density = screen_resolutions.get(qualifier.split('-')[0], '65534')
        icons_src[density] = path
    if not icons_src.get('-1') and '160' in icons_src:
        icons_src['-1'] = icons_src['160']
    if not has_png:
        # path = arsc.get_resolved_res_configs(icon_id, default_config)[0][1]
        # axml = AXMLPrinter(apkobject.get_file(path))
        axml = AXMLPrinter(apkobject.get_file(icons_src['65534']))
        print(axml.get_xml())
        svg = render_adaptive_icon(apkobject, axml, arsc)
        svg_str = XMLElementTree.tostring(element=svg)
        XMLElementTree.ElementTree(element=svg).write('out.svg')
        svg2png(bytestring=svg_str, write_to='output.png')


def render_adaptive_icon(apkobject, axml, arsc):
    # print(axml.get_xml())
    xml = axml.get_xml_obj()
    if len(xml.nsmap) > 0:
        # one of them surely will be the Android one, or its corrupt
        xmlns = XMLNS_ANDROID
    else:
        # strange but sometimes the namespace is blank.  This seems to
        # only happen with the Bromite/Chromium APKs
        xmlns = '{}'

    background = xml.find('background').get(xmlns + 'drawable')
    foreground = xml.find('foreground').get(xmlns + 'drawable')
    print(background, foreground)
    foreground_res_type, foreground_res = parse_drawable(foreground, apkobject, arsc)
    background_res_type, background_res = parse_drawable(background, apkobject, arsc)

    svg = XMLElementTree.Element('svg')

    svg.set('id', 'vector')
    svg.set('xmlns', 'http://www.w3.org/2000/svg')
    svg.set('width', '108')
    svg.set('height', '108')
    svg.set(
        'viewBox',
        # TODO: Should put background into a group
        '0 0 {viewportWidth} {viewportHeight}'.format(
            viewportWidth=foreground_res.get(xmlns + 'viewportWidth'),
            viewportHeight=foreground_res.get(xmlns + 'viewportHeight'),
        ),
    )

    if background_res_type == 'color':
        svg.set('style', 'background-color:{}'.format(background_res))
    if background_res_type == 'drawable':
        for vd_node in background_res:
            svg.append(map_node(vd_node))

    if foreground_res_type == 'color':
        svg.set('style', 'background-color:{}'.format(background_res))
    if foreground_res_type == 'drawable':
        for vd_node in foreground_res:
            svg.append(map_node(vd_node))

    return svg


def parse_drawable(res_str, apkobject, arsc):
    res_id, package_name = arsc.parse_id(res_str)
    if not package_name:
        package_name = apkobject.get_package()
    if package_name == 'android':
        apkobject = APK('framework-res.apk')
        arsc = apkobject.get_android_resources()
    res_type = arsc.get_id(package_name, res_id)[0]
    res = arsc.get_resolved_res_configs(res_id, default_config)[0][1]
    if res_type == 'color':
        res = map_color(res)
    elif res_type == 'drawable':
        res = AXMLPrinter(apkobject.get_file(res)).get_xml_obj()
    else:
        res = None

    return res_type, res


def map_color(vd_color):
    return vd_color[0] + vd_color[3:] + vd_color[1:3]


def map_transform(trans_dict):
    '''
    Build transform attribute from a dict.
    The transformations are defined in the same coordinates as the viewport.
    And the transformations are applied in the order of scale, rotate then translate.
    '''
    trans_list = []

    pivot = None

    # SVG doesn't support pivot so use translate twice instead.
    if trans_dict.get('pivotX') or trans_dict.get('pivotY'):
        pivot = (float(trans_dict.get('pivotX', 0)), float(trans_dict.get('pivotY', 0)))
        trans_list.append(
            'translate({x} {y})'.format(
                x=-pivot[0],
                y=-pivot[1],
            )
        )

    if trans_dict.get('scaleX') or trans_dict.get('scaleY'):
        trans_list.append(
            'scale({x} {y})'.format(
                x=trans_dict.get('scaleX', 1),
                y=trans_dict.get('scaleY', 1),
            )
        )

    if trans_dict.get('rotation'):
        trans_list.append('rotate({})'.format(trans_dict['rotation']))

    if pivot:
        trans_list.append(
            'translate({x} {y})'.format(
                x=pivot[0],
                y=pivot[1],
            )
        )

    if trans_dict.get('translateX') or trans_dict.get('translateY'):
        trans_list.append(
            'translate({x} {y})'.format(
                x=trans_dict.get('translateX', 0),
                y=trans_dict.get('translateY', 0),
            )
        )

    return ' '.join(trans_list)


def map_node(vd_node):
    # TODO: trimPathStart, trimPathEnd, trimPathOffset
    ATTRS_KEY_MAP = {
        'name': 'id',
        'pathData': 'd',
        'fillColor': 'fill',
        'strokeColor': 'stroke',
        'strokeWidth': 'stroke-width',
        'strokeAlpha': 'stroke-opacity',
        'fillAlpha': 'fill-opacity',
        'strokeLineCap': 'stroke-linecap',
        'strokeLineJoin': 'stroke-linejoin',
        'strokeMiterLimit': 'stroke-miterlimit',
        'fillType': 'fill-rule',
    }

    ATTRS_VALUE_MAP = {
        'fillColor': map_color,
        'strokeColor': map_color,
        'fillType': str.lower,
    }

    if vd_node.tag == 'group':
        TRANSFORM = [
            'pivotX',
            'pivotY',
            'rotation',
            'scaleX',
            'scaleY',
            'translateX',
            'translateY',
        ]
        svg_node = XMLElementTree.Element('g')

        transform = dict()

        for k, v in vd_node.items():
            k = k.split('}')[1]
            if k in TRANSFORM:
                transform[k] = v
            else:
                if ATTRS_KEY_MAP.get(k):
                    svg_node.set(ATTRS_KEY_MAP[k], v)

        if transform:
            svg_node.set('transform', map_transform(transform))

        for vd_child in vd_node:
            svg_child = map_node(vd_child)
            if svg_child.tag == 'clip-path':
                svg_node.set('clip-path', 'url(#{})'.format(svg_child.get('id')))
            svg_node.append()

    elif vd_node.tag == 'path':
        svg_node = XMLElementTree.Element('path')

        for k, v in vd_node.items():
            k = k.split('}')[1]
            svg_attr_name = ATTRS_KEY_MAP.get(k)
            if svg_attr_name:
                mapper = ATTRS_VALUE_MAP.get(k)
                if mapper:
                    svg_node.set(svg_attr_name, mapper(v))
                else:
                    svg_node.set(svg_attr_name, v)

    elif vd_node.tag == 'clip-path':
        svg_node = XMLElementTree.Element('clip-path')

        for k, v in vd_node.items():
            k = k.split('}')[1]
            svg_attr_name = ATTRS_KEY_MAP.get(k)
            if svg_attr_name:
                svg_node.set(svg_attr_name, v)

    else:
        return

    return svg_node
