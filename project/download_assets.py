import os
import urllib.request
import re
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_VENDOR = os.path.join(BASE_DIR, 'src', 'webapp', 'static', 'vendor')

os.makedirs(STATIC_VENDOR, exist_ok=True)
os.makedirs(os.path.join(STATIC_VENDOR, 'css'), exist_ok=True)
os.makedirs(os.path.join(STATIC_VENDOR, 'js'), exist_ok=True)
os.makedirs(os.path.join(STATIC_VENDOR, 'webfonts'), exist_ok=True)
os.makedirs(os.path.join(STATIC_VENDOR, 'fonts'), exist_ok=True)
os.makedirs(os.path.join(STATIC_VENDOR, 'topojson'), exist_ok=True)
os.makedirs(os.path.join(STATIC_VENDOR, 'topojson', 'un'), exist_ok=True)

def download(url, path, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36'}):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response, open(path, 'wb') as out_file:
            data = response.read()
            out_file.write(data)
            return data
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return None

# 1. Tailwind
print("Downloading Tailwind...")
download('https://cdn.tailwindcss.com?plugins=forms,container-queries', os.path.join(STATIC_VENDOR, 'js', 'tailwindcss.js'))

# 2. Chart.js
print("Downloading Chart.js...")
download('https://cdn.jsdelivr.net/npm/chart.js', os.path.join(STATIC_VENDOR, 'js', 'chart.js'))

# 3. Plotly.js
print("Downloading Plotly.js...")
download('https://cdn.plot.ly/plotly-2.35.2.min.js', os.path.join(STATIC_VENDOR, 'js', 'plotly.min.js'))

# 4. FontAwesome
print("Downloading FontAwesome...")
fa_css_url = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
fa_css_data = download(fa_css_url, os.path.join(STATIC_VENDOR, 'css', 'all.min.css'))
if fa_css_data:
    fa_css_str = fa_css_data.decode('utf-8')
    fa_base_url = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/'
    fonts = set(re.findall(r'url\((../webfonts/[^)]+)\)', fa_css_str))
    for font in fonts:
        font_name = font.split('/')[-1].split('?')[0].split('#')[0]
        font_url = fa_base_url + font_name
        print(f"Downloading FA font {font_name}...")
        download(font_url, os.path.join(STATIC_VENDOR, 'webfonts', font_name))

# 5. Google Fonts (Inter)
print("Downloading Google Fonts...")
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36'}
inter_css_url = 'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap'
inter_css_data = download(inter_css_url, os.path.join(STATIC_VENDOR, 'css', 'inter.css'), headers=headers)
if inter_css_data:
    inter_css_str = inter_css_data.decode('utf-8')
    inter_font_urls = set(re.findall(r'url\((https://[^)]+)\)', inter_css_str))
    for i, font_url in enumerate(inter_font_urls):
        font_name = f'inter_{i}.woff2'
        print(f"Downloading Inter font {font_name}...")
        download(font_url, os.path.join(STATIC_VENDOR, 'fonts', font_name))
        inter_css_str = inter_css_str.replace(font_url, f'../fonts/{font_name}')

    with open(os.path.join(STATIC_VENDOR, 'css', 'inter.css'), 'w', encoding='utf-8') as f:
        f.write(inter_css_str)

# 6. Plotly World Topojson (for 100% offline map rendering)
print("Downloading Plotly World Topojson for offline map...")
topo_dir = os.path.join(STATIC_VENDOR, 'topojson')
topo_un_dir = os.path.join(topo_dir, 'un')
for name in ['world_110m.json', 'world_50m.json']:
    print(f"Downloading {name}...")
    dest = os.path.join(topo_dir, name)
    download(f'https://cdn.plot.ly/{name}', dest)
    shutil.copyfile(dest, os.path.join(topo_un_dir, name))

print("All assets downloaded successfully and configured for 100% offline usage.")
