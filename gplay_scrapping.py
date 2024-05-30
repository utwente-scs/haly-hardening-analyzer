import sys
from google_play_scraper import app as gplay_app
from google_play_scraper.exceptions import NotFoundError
import json, time

headers = {'User-Agent': 'Name - Email'}
final_data = {}
apps = {}

# ID file name from arguments
ids_file = sys.argv[1]
out_file = sys.argv[2]

with open(ids_file, "r") as ids_file:
	ids = json.load(ids_file)
final_data = {
    'crawl_date': time.strftime('%Y-%m-%d %H:%M:%S'),
    'apps': []
}

for id in ids['apps']:
    try:
        app = {}
        app['ios_bundle_id'] = id['ios_bundle_id']
        app_id = id['android_id']
        app['android_id'] = app_id
        app_info = gplay_app(app_id)
        app['android_name'] = app_info['title']
        app['android_url'] = app_info['url']
        app['android_icon'] = app_info['icon']
        app['android_publisher'] = app_info['developer']
        app['android_category'] = app_info['genre']
        #print(app)
        final_data['apps'].append(app)

        with open(out_file, "w") as f:
	        json.dump(final_data, f)
    except (IndexError, NotFoundError):
        # App not found
        print('[!] No Android version found of app', id)
