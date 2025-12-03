import os
from bs4 import BeautifulSoup 

# CONFIGURATION: Map your Bookmark Folders to Repo Paths
FOLDER_MAP = {
    # 1. References (JS Tools)
    # We map this to a separate file in 'tools' so you can move them to Arsenal later
    'References': 'tools/JavaScript_Backups.md',

    # 2. Web Scraping
    'Web Scraping': '04-Web-Scraping/Web_Miners.md',

    # 3. Blogs & Books
    'Blogs': '07-bOOks/bOOks.md',
    'Books': '07-bOOks/bOOks.md',

    # 4. Red Team
    'Red Team': '01-Red-Team/Web-App-Pentest.md',

    # 5. Threat Intel
    'Threat Intel': '03-Threat-Intel/Feeds.md',

    # 6. Networking
    'Networking': '05-Networking/New_Twerking.md',

    # 7. Repo Refs
    'Repo Refs': '06-Repo-Refs/Legend_Repos.md'
}

def sanitize(text):
    if not text: return "Untitled"
    # Remove pipes and newlines to prevent breaking Markdown tables
    return text.strip().replace('|', '-').replace('\n', ' ')

def main():
    # 1. ROBUST PATH FINDING
    script_location = os.path.dirname(os.path.abspath(__file__))
    bookmarks_file = os.path.join(script_location, 'bookmarks.html')
    repo_root = os.path.abspath(os.path.join(script_location, ".."))

    if not os.path.exists(bookmarks_file):
        print(f"❌ Error: 'bookmarks.html' not found at {bookmarks_file}")
        return

    print("🚀 Starting Migration...")
    
    try:
        with open(bookmarks_file, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
    except UnicodeDecodeError:
        print("⚠️ UTF-8 failed, trying Latin-1 encoding...")
        with open(bookmarks_file, 'r', encoding='latin-1') as f:
            soup = BeautifulSoup(f, 'html.parser')

    headers = soup.find_all('h3')
    print(f"ℹ️  Found {len(headers)} folders in file.")

    for header in headers:
        category = header.text.strip()
        
        # --- EXCLUSION LOGIC ---
        # Explicitly skip TPL webs
        if "TPL webs" in category:
            print(f"🚫 Skipping Private Folder: '{category}'")
            continue
        # -----------------------

        print(f"\n📂 Processing folder: '{category}'")

        # 1. Determine Target Path
        target_path = None
        for key in FOLDER_MAP:
            if key.lower() in category.lower():
                target_path = FOLDER_MAP[key]
                print(f"   -> MATCH: Mapped to '{target_path}'")
                break
        
        if not target_path:
            clean_cat = "".join(x for x in category if x.isalnum() or x in " -_")
            target_path = f"99-Unsorted/{clean_cat}.md"
            print(f"   -> NO MATCH: Moving to '{target_path}'")

        # 2. Setup File System
        full_path = os.path.join(repo_root, target_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        # 3. Find Links
        dl = header.find_next_sibling('dl')
        if not dl: dl = header.find_next('dl')
        
        if not dl:
            print("   ⚠️  Skipping: No link list found.")
            continue

        links_found = []
        for link in dl.find_all('a'): 
            name = sanitize(link.text)
            url = link.get('href')
            
            if not url: continue

            # --- CUSTOM LINK HANDLING ---
            # If it is a JavaScript tool (References folder)
            if url.startswith('javascript:'):
                # We save it as a Code Block so it doesn't break the markdown table
                # This keeps the code safe in 'tools/JavaScript_Backups.md'
                links_found.append(f"| ⚡ {name} | `JavaScript Code (See Raw File)` |")
            
            # If it is a normal http/https link
            elif not url.startswith('place:'):
                 links_found.append(f"| {name} | {url} |")

        # 4. Write to File
        if links_found:
            with open(full_path, 'a', encoding='utf-8') as md:
                if os.stat(full_path).st_size == 0:
                     md.write(f"# {category}\n\n| Tool / Resource | Link |\n|---|---|\n")
                md.write("\n".join(links_found) + "\n")
            
            print(f"   ✅ Saved {len(links_found)} links.")
        else:
            print("   ⚠️  Folder empty (0 valid links found).")

if __name__ == "__main__":
    main()