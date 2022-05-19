import {
  closeSync,
  copyFileSync,
  openSync,
  readdirSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from 'fs';
import { join } from 'path';
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error, @typescript-eslint/ban-ts-comment
// @ts-ignore
import replace from 'replace';

const copyFiles = (src: string, dest = src): void => {
  const destList = dest.split(' ');
  src.split(' ').forEach((file, i) => {
    copyFileSync(file, join(__dirname, 'dist', destList[i]));
  });
};

// remove files other than output
readdirSync(join(__dirname, 'dist')).forEach((file) => {
  if (!/^crypto\.js|index\.(d\.ts|js)$/.test(file)) unlinkSync(join(__dirname, 'dist', file));
});

// copy relevant files to dist
copyFiles('.npmignore LICENSE.md README.md');
copyFiles('package-dist.json', 'package.json');

// merge type declarations
const data = readFileSync(join(__dirname, 'dist', 'index.d.ts')).toString();
const fd = openSync(join(__dirname, 'dist', 'index.d.ts'), 'w+');
writeSync(fd, `${readFileSync(join(__dirname, 'src', 'types.d.ts')).toString()}\n${data}`);
closeSync(fd);

// remove reference comments and empty lines
[/^\/{3} <reference [^]*?\n/gm, /^\s*?\n+/gm].forEach((regex) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  replace({
    regex,
    replacement: '',
    paths: ['./dist/index.d.ts', './dist/index.js'],
    silent: true,
  });
});
