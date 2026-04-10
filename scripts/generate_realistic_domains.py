#!/usr/bin/env python3
"""
Generate realistic domain list for Tranco top 10k testing.
Creates diverse, realistic-looking domains for false-positive testing.
"""
import random


def generate_realistic_domains(count=10000):
    """Generate realistic-looking domain names."""
    
    # Common TLDs
    tlds = ['.com', '.org', '.net', '.io', '.co', '.us', '.uk', '.de', '.fr', '.jp']
    
    # Common prefixes
    prefixes = [
        'google', 'youtube', 'facebook', 'amazon', 'netflix', 'twitter', 'instagram',
        'linkedin', 'reddit', 'wikipedia', 'github', 'stackoverflow', 'medium', 'quora',
        'pinterest', 'tumblr', 'wordpress', 'blogspot', 'vimeo', 'flickr', 'imgur',
        'etsy', 'kickstarter', 'shopify', 'zoom', 'slack', 'discord', 'telegram',
        'whatsapp', 'signal', 'tiktok', 'snapchat', 'twitch', 'spotify', 'apple',
        'microsoft', 'adobe', 'nvidia', 'intel', 'ibm', 'oracle', 'salesforce',
        'dropbox', 'box', 'trello', 'asana', 'notion', 'figma', 'canva', 'dribbble',
        'behance', 'deviantart', 'codepen', 'jsfiddle', 'pastebin', 'bitbucket',
        'gitlab', 'sourceforge', 'apache', 'nginx', 'python', 'ruby', 'php', 'java',
        'javascript', 'typescript', 'react', 'vue', 'angular', 'ember', 'django',
        'rails', 'laravel', 'spring', 'flask', 'express', 'node', 'golang', 'rust'
    ]
    
    # Common patterns
    patterns = [
        '{}', 'get{}', 'try{}', 'use{}', 'my{}', 'new{}', 'best{}', 'top{}',
        'free{}', 'online{}', 'secure{}', 'fast{}', 'easy{}', 'simple{}',
        'pro{}', 'plus{}', 'hub{}', 'lab{}', 'app{}', 'site{}', 'web{}',
        'cloud{}', 'data{}', 'api{}', 'dev{}', 'code{}', 'tech{}', 'io{}'
    ]
    
    domains = set()
    
    # Add top 100 real popular domains
    top_100 = [
        'google.com', 'youtube.com', 'facebook.com', 'baidu.com', 'wikipedia.org',
        'yahoo.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
        'amazon.com', 'reddit.com', 'whatsapp.com', 'pinterest.com', 'tumblr.com',
        'wordpress.org', 'blogspot.com', 'medium.com', 'github.com', 'stackexchange.com',
        'quora.com', 'vimeo.com', 'flickr.com', 'soundcloud.com', 'imgur.com',
        'slideshare.net', 'etsy.com', 'kickstarter.com', 'indiegogo.com', 'producthunt.com',
        'dribbble.com', 'behance.net', 'deviantart.com', 'codepen.io', 'jsfiddle.net',
        'pastebin.com', 'gist.github.com', 'bitbucket.org', 'gitlab.com', 'sourceforge.net',
        'apache.org', 'mozilla.org', 'ubuntu.com', 'archlinux.org', 'fedora.org',
        'debian.org', 'opensuse.org', 'centos.org', 'nginx.org', 'python.org',
        'ruby-lang.org', 'php.net', 'perl.org', 'golang.org', 'rust-lang.org',
        'scala-lang.org', 'elixir-lang.org', 'clojure.org', 'haskell.org', 'erlang.org',
        'nodejs.org', 'reactjs.org', 'vuejs.org', 'angular.io', 'emberjs.com',
        'backbonejs.org', 'metor.com', 'django.com', 'rails.org', 'laravel.com'
    ]
    
    domains.update(top_100)
    
    # Generate remaining domains
    while len(domains) < count:
        prefix = random.choice(prefixes)
        pattern = random.choice(patterns)
        tld = random.choice(tlds)
        
        domain = pattern.format(prefix) + tld
        domains.add(domain)
    
    return list(domains)[:count]

if __name__ == '__main__':
    import os
    os.makedirs('tests/fp_corpus/data', exist_ok=True)
    
    print("Generating realistic domain list...")
    domains = generate_realistic_domains(10000)
    
    with open('tests/fp_corpus/data/tranco_top_10k.txt', 'w') as f:
        f.write('\n'.join(domains))
    
    print(f"✓ Generated {len(domains)} realistic domains")
    print(f"  First 10: {domains[:10]}")
    print(f"  Last 10: {domains[-10:]}")
