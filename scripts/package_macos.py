"""Package an .app with UTF-8 filenames and Unix executable permissions."""
from pathlib import Path
import sys
import zipfile

app, destination = map(Path, sys.argv[1:3])
if not app.is_dir() or app.suffix != '.app':
    raise SystemExit('Expected an existing .app directory')
destination.parent.mkdir(parents=True, exist_ok=True)
temporary = destination.with_suffix('.zip.tmp')
with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
    archive.write(app, app.name)
    for path in sorted(app.rglob('*')):
        if path.name.startswith('._') or path.name == '.DS_Store':
            continue
        if path.is_symlink():
            raise SystemExit('Unexpected symlink in statically linked application')
        archive.write(path, path.relative_to(app.parent).as_posix())
temporary.replace(destination)
print(destination)
