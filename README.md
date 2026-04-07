# BLOG

Official blog of Stalin S (w4nn4d13).

## About

This site publishes cybersecurity research and technical writeups, with a focus on:

- CVE research
- Vulnerability analysis
- Penetration testing
- AI-driven security research

## Author

- Name: Stalin S (w4nn4d13)
- GitHub: https://github.com/Stalin-143
- LinkedIn: https://www.linkedin.com/in/stalin-s-a310882a0/
- X: https://x.com/0x5t4l1n

## Tech Stack

- Jekyll
- Chirpy theme
- Sass
- JavaScript (npm build pipeline)

## Local Development

1. Install Ruby gems:

```bash
bundle config set --local path 'vendor/bundle'
bundle install
```

2. Run the site:

```bash
./tools/run.sh
```

3. Open:

```text
http://127.0.0.1:4000
```

## Build

```bash
./tools/test.sh
```

## Writeup Publishing

Add posts in `_posts` using this filename format:

```text
YYYY-MM-DD-title.md
```

Example:

```text
_posts/2026-04-07-first-writeup.md
```

## Deployment

This repository is configured to push to:

```text
git@github.com:Stalin-143/BLOG.git
```

Push updates:

```bash
git add -A
git commit -m "update blog"
git push
```
