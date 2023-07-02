import requests
import json
import time
from os.path import exists, dirname, join
from google_play_scraper import app as gplay_app
from google_play_scraper.exceptions import NotFoundError
from urllib.parse import quote

# Provide contact info in requests when crawling
headers = {'User-Agent': 'Wilco van Beijnum - a.c.w.vanbeijnum@student.utwente.nl'}

apps_file = join(dirname(__file__), 'apps.json')

if exists(join(dirname(__file__), 'scrapingant-key.txt')):
    with open(join(dirname(__file__), 'scrapingant-key.txt'), 'r') as f:
        api_key = f.read().strip()
else:
    print('[!] Please create a scrapingant-key.txt file with a ScrapingAnt API key. You can create one for free at https://scrapingant.com/')
    exit(1)

def scrapingant_get(url, response_is_json=True):
    response = requests.get('https://api.scrapingant.com/v2/general?url='+quote(url)+'&return_page_source=true&x-api-key='+api_key, headers=headers).text
    return json.loads(response) if response_is_json else response


# Get iOS app info from top charts
if exists(apps_file):
    with open(apps_file, 'r') as f:
        data = json.load(f)
else:
    # JSON.stringify(Array.from(document.querySelectorAll('.we-genre-filter__item')).map(e => ({url: e.href, name: e.querySelector('.we-genre-filter__name').textContent.trim()})))
    categories = json.loads('[{"url":"https://apps.apple.com/us/charts/iphone/books-apps/6018","name":"Books"},{"url":"https://apps.apple.com/us/charts/iphone/business-apps/6000","name":"Business"},{"url":"https://apps.apple.com/us/charts/iphone/developer-tools-apps/6026","name":"Developer Tools"},{"url":"https://apps.apple.com/us/charts/iphone/education-apps/6017","name":"Education"},{"url":"https://apps.apple.com/us/charts/iphone/entertainment-apps/6016","name":"Entertainment"},{"url":"https://apps.apple.com/us/charts/iphone/finance-apps/6015","name":"Finance"},{"url":"https://apps.apple.com/us/charts/iphone/food-drink-apps/6023","name":"Food & Drink"},{"url":"https://apps.apple.com/us/charts/iphone/graphics-design-apps/6027","name":"Graphics & Design"},{"url":"https://apps.apple.com/us/charts/iphone/health-fitness-apps/6013","name":"Health & Fitness"},{"url":"https://apps.apple.com/us/charts/iphone/kids-apps/36?ageId=0","name":"Kids"},{"url":"https://apps.apple.com/us/charts/iphone/lifestyle-apps/6012","name":"Lifestyle"},{"url":"https://apps.apple.com/us/charts/iphone/magazines-newspapers-apps/6021","name":"Magazines & Newspapers"},{"url":"https://apps.apple.com/us/charts/iphone/medical-apps/6020","name":"Medical"},{"url":"https://apps.apple.com/us/charts/iphone/music-apps/6011","name":"Music"},{"url":"https://apps.apple.com/us/charts/iphone/navigation-apps/6010","name":"Navigation"},{"url":"https://apps.apple.com/us/charts/iphone/news-apps/6009","name":"News"},{"url":"https://apps.apple.com/us/charts/iphone/photo-video-apps/6008","name":"Photo & Video"},{"url":"https://apps.apple.com/us/charts/iphone/productivity-apps/6007","name":"Productivity"},{"url":"https://apps.apple.com/us/charts/iphone/reference-apps/6006","name":"Reference"},{"url":"https://apps.apple.com/us/charts/iphone/shopping-apps/6024","name":"Shopping"},{"url":"https://apps.apple.com/us/charts/iphone/social-networking-apps/6005","name":"Social Networking"},{"url":"https://apps.apple.com/us/charts/iphone/sports-apps/6004","name":"Sports"},{"url":"https://apps.apple.com/us/charts/iphone/travel-apps/6003","name":"Travel"},{"url":"https://apps.apple.com/us/charts/iphone/utilities-apps/6002","name":"Utilities"},{"url":"https://apps.apple.com/us/charts/iphone/weather-apps/6001","name":"Weather"},{"url":"https://apps.apple.com/us/charts/iphone/top-free-games/6014","name":"Games"}]')

    data = {
        'crawl_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'apps': []
    }
    apps = {}
    for category in categories:
        t = time.time()

        name = category['name']
        url = category['url'] + '?chart=top-free'

        print('Crawling iTunes category', name)

        response = requests.get(url, headers=headers).text
        app_data = response.split('<script type="fastboot/shoebox" id="shoebox-media-api-cache-apps">')[1].split('</script>')[0]
        app_data = json.loads(app_data)

        for (key, value) in app_data.items():
            if 'apps' not in key:
                continue

            value = json.loads(value)

            i = 1
            for app in value['d']['apps'][0]['data']:
                attrs = app['attributes']
                platform_attrs = attrs['platformAttributes']['ios']

                apps[app['id']] = {
                    'ios_name': attrs['name'],
                    'ios_url': attrs['url'],
                    'ios_id': app['id'],
                    'ios_bundle_id': platform_attrs['bundleId'],
                    'ios_min_os': platform_attrs['minimumMacOSVersion'] if 'minimumMacOSVersion' in platform_attrs else None,
                    'ios_icon': platform_attrs['artwork']['url'],
                    'ios_publisher': attrs['artistName'],
                    'ios_rank': attrs['chartPositions']['appStore']['position'] if name != 'Games' else i,
                    'ios_category': attrs['chartPositions']['appStore']['genreName'] if name != 'Games' else 'Games',
                }

                i += 1

        # Max. 1 request per second
        delta = time.time() - t
        if delta < 1:
            time.sleep(1 - delta)

    data['apps'] = list(apps.values())
    with open(apps_file, 'w') as f:
        json.dump(data, f)


# Search for Android app info using AppRanking
for app in data['apps']:
    if 'android_id' in app:
        continue

    t = time.time()

    print('Scraping app on AppRanking', app['ios_name'])

    ios_id = app['ios_id']
    response = requests.get(f'https://www.appranking.com/app-profile/{ios_id}/US/as', headers=headers).text

    try:
        app['android_id'] = response.split('gpId="')[1].split('"')[0]

        app_info = gplay_app(app['android_id'])
        app['android_name'] = app_info['title']
        app['android_url'] = app_info['url']
        app['android_icon'] = app_info['icon']
        app['android_publisher'] = app_info['developer']
        app['android_category'] = app_info['genre']

        with open(apps_file, 'w') as f:
            json.dump(data, f)
    except (IndexError, NotFoundError):
        # App not found
        print('[!] No Android version found of app', app['ios_name'])
        app['android_id'] = None

    # Max. 1 request per second
    delta = time.time() - t
    if delta < 1:
        time.sleep(1 - delta)

with open(apps_file, 'w') as f:
    json.dump(data, f)


# Search for Android app info using AlternativeTo
api_hash = 'EBawJgPpkTdmnj1Y3v6Xi'
response = scrapingant_get('https://alternativeto.net/', False)
api_hash = response.split('/_buildManifest.js')[0].split('<script src="/_next/static/')[-1]

start_page = data['alternativeto_page'] + 1 if 'alternativeto_page' in data else 1
max_page = 100

for page in range(start_page, max_page + 1):
    alternativeto_apps = {}

    print(f'Scraping page {page} on AlternativeTo')
    
    page_query = ''
    if page > 1:
        page_query = f'p={page}&'
    
    attempt = 0
    error = None
    while attempt < 3:
        try:
            url = f'https://alternativeto.net/_next/data/{api_hash}/browse/platform/android.json?{page_query}browse=platform&appList=android'
            page_apps = scrapingant_get(url)
            break
        except json.decoder.JSONDecodeError as e:
            error = e
            attempt += 1
            time.sleep(1)
    else:
        raise error

    for app in page_apps['pageProps']['items']:
        if not any(platform['urlName'] == 'iphone' for platform in app['platforms']):
            # Not an app with an Android and iOS version
            continue

        t = time.time()

        slug = app['urlName']

        print(f'Scraping {slug} on AlternativeTo')

        attempt = 0
        error = None
        while attempt < 3:
            try:
                url = f'https://alternativeto.net/_next/data/{api_hash}/software/{slug}/about.json'
                app_info = scrapingant_get(url)
                break
            except json.decoder.JSONDecodeError as e:
                error = e
                attempt += 1
                time.sleep(1)
        else:
            raise error

        android_id = None
        ios_id = None
        for link in app_info['pageProps']['mainItem']['externalLinks']:
            if link['name'] == 'Google Play Store':
                android_id = link['url'].split('id=')[1].split('&')[0] if 'id=' in link['url'] else None
            elif link['name'] == 'iPhone App Store':
                ios_id = link['url'].split('/')[-1].split('?')[0][2:]
        
        if android_id is not None and ios_id is not None:
            alternativeto_apps[ios_id] = android_id

        # Max. 1 request per second
        delta = time.time() - t
        if delta < 1:
            time.sleep(1 - delta)

    for app in data['apps']:
        if app['android_id'] is not None:
            continue

        if app['ios_id'] in alternativeto_apps:
            print(f"Found alternative for {app['ios_name']}")

            try:
                app_info = gplay_app(app['android_id'])

                app['android_id'] = alternativeto_apps[app['ios_id']]
                app['android_name'] = app_info['title']
                app['android_url'] = app_info['url']
                app['android_icon'] = app_info['icon']
                app['android_publisher'] = app_info['developer']
                app['android_category'] = app_info['genre']
            except Exception:
                print('[!] Failed to get info from play store for', alternativeto_apps[app['ios_id']])
                app['android_id'] = None

    data['alternativeto_page'] = page
    with open(apps_file, 'w') as f:
        json.dump(data, f)


# Search for Android app info on Play Store by asking user to select the right app
start = data['playstore_page'] if 'playstore_page' in data else 0
data['playstore_page'] = start
for app in data['apps'][start:]:
    data['playstore_page'] += 1

    if app['android_id'] is not None:
        continue

    query = f"{app['ios_name']} {app['ios_publisher']}"
    print('\n' * 100) # Clear screen
    print(f"Searching for \033[1m{app['ios_name']} - {app['ios_publisher']}\033[0m ({app['ios_bundle_id']}) on Play Store")
    response = requests.get('https://play.google.com/store/search?c=apps&q=' + quote(query)).text
    query_results = []
    for result in response.split('/store/apps/details?id=')[1:]:
        try:
            title_class = [item for item in ['DdYX5', 'vWM94c'] if item in result][0]
            publisher_class = [item for item in ['wMUdtb', 'LbQbAe'] if item in result][0]
            package_id = result.split('"')[0]
            title = result.split(f'class="{title_class}">')[1].split('</')[0].replace('&amp;', '&').replace('&#39;', "'")
            publisher = result.split(f'class="{publisher_class}">')[1].split('</')[0].replace('&amp;', '&').replace('&#39;', "'")
            query_results.append((package_id, title, publisher))

            if len(query_results) == 5:
                break
        except IndexError:
            pass

    if len(query_results) == 0:
        with open(apps_file, 'w') as f:
            json.dump(data, f)

        print('No results found')
        continue

    for i, result in enumerate(query_results):
        if (result[1] == app['ios_name'] and result[2] == app['ios_publisher']) or result[0].lower() in app['ios_bundle_id'].lower() or app['ios_bundle_id'].lower() in result[0].lower():
            print('!', end='')
        print(f"{i+1}. \033[1m{result[1]} - {result[2]}\033[0m ({result[0]})")

    correct_result = input(f'Please enter the number of the app matching \033[1m{result[1]}{app["ios_name"]} - {app["ios_publisher"]}\033[0m ({app["ios_bundle_id"]}) (enter 0 if no match, press ENTER for match 1): ')
    if correct_result == '0':
        with open(apps_file, 'w') as f:
            json.dump(data, f)

        continue
    else:
        if not correct_result:
            # 1 by default
            correct_result = '1'
        correct_result = int(correct_result) - 1

        try:
            app_info = gplay_app(query_results[correct_result][0])

            app['android_id'] = query_results[correct_result][0]
            app['android_name'] = app_info['title']
            app['android_url'] = app_info['url']
            app['android_icon'] = app_info['icon']
            app['android_publisher'] = app_info['developer']
            app['android_category'] = app_info['genre']

            with open(apps_file, 'w') as f:
                json.dump(data, f)
        except Exception:
            print('[!] Failed to get info from play store for', query_results[correct_result][0])
            app['android_id'] = None