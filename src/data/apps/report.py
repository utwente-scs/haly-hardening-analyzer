import json
from os.path import join, dirname

with open(join(dirname(__file__), 'apps.json')) as f:
    data = json.load(f)

# HTML report
doc = '<html><head><style>body{font-family:sans-serif}th{text-align:left}td:first-child,td:nth-child(2){padding:5px 10px 5px 0}</style></head><body>'

def add_app_table_header():
    global doc

    doc += '<tr>'
    # Icon
    doc += '<th>iOS</th>'
    doc += '<th>Android</th>'
    # Name
    doc += '<th>iOS name</th>'
    doc += '<th>Android name</th>'
    # Publisher
    doc += '<th>iOS publisher</th>'
    doc += '<th>Android publisher</th>'

def add_app_table_entry(app):
    global doc

    doc += '<tr>'
    # Icon
    doc += '<td><img src="%s" width="75" height="75"></td>' % app['ios_icon'].replace('{w}x{h}{c}.{f}', '100x100w.png')
    doc += '<td><img src="%s" width="75" height="75"></td>' % app['android_icon']
    # Name
    doc += '<td>%s</td>' % app['ios_name']
    doc += '<td>%s</td>' % app['android_name']
    # Publisher
    doc += '<td>%s</td>' % app['ios_publisher']
    doc += '<td>%s</td>' % app['android_publisher']
    

dups = []
for app in data['apps']:
    for other_app in data['apps']:
        if app['ios_id'] != other_app['ios_id'] and app['android_id'] is not None and app['android_id'] == other_app['android_id']:
            dups.append((app, other_app))

doc += '<h1>Duplicate apps</h1>'
if len(dups) == 0:
    doc += '<p>No apps found with the same Android app ID</p>'
else:
    doc += '<table>'
    add_app_table_header()
    for app, other_app in dups:
        add_app_table_entry(app)
        add_app_table_entry(other_app)
        doc += '<tr><td colspan="6" height="20"></td></tr>'
    doc += '</table>'

doc += '<h1>All apps</h1><table>'
add_app_table_header()
for app in data['apps']:
    if app['android_id'] is None:
        continue

    add_app_table_entry(app)
doc += '</table>'

doc += '</body></html>'

with open(join(dirname(__file__), 'apps.html'), 'w') as f:
    f.write(doc)

# YAML list
data['apps'].sort(key=lambda x: x['ios_rank'])

yaml = 'apps:\n'

yaml += '  android:\n'
rank = None
for app in data['apps']:
    if app['android_id'] is None:
        continue

    if app['ios_rank'] != rank:
        # Add comment of rank
        rank = app['ios_rank']
        yaml += '    # %d\n' % rank

    yaml += '    - %s\n' % app['android_id']

yaml += '  ios:\n'
rank = None
for app in data['apps']:
    if app['android_id'] is None:
        continue

    if app['ios_rank'] != rank:
        # Add comment of rank
        rank = app['ios_rank']
        yaml += '    # %d\n' % rank

    yaml += '    - %s\n' % app['ios_bundle_id']

with open(join(dirname(__file__), 'apps.yaml'), 'w') as f:
    f.write(yaml)
