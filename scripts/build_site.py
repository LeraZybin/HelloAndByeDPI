"""Build the static GitHub Pages site with the current application version."""
from pathlib import Path
import re
import shutil

root = Path(__file__).resolve().parents[1]
version = re.search(r'project\(ByeDPI_Desktop VERSION ([0-9.]+)', (root / 'CMakeLists.txt').read_text()).group(1)
destination = root / 'build-site'
destination.mkdir(exist_ok=True)
for name in ('index.html', 'style.css', 'app.js'):
    text = (root / 'website' / name).read_text()
    (destination / name).write_text(text.replace('__VERSION__', version))
shutil.copy2(root / 'assets/icon.png', destination / 'icon.png')
(destination / '.nojekyll').touch()
print(f'Website {version}: {destination}')
