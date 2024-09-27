import argparse
import os
from email_analyzer import EmailAnalyzer
from concurrent.futures import ThreadPoolExecutor, as_completed

def process_file(file_path, args):
    """Process a single email file."""
    results = {}
    try:
        with open(file_path, "r") as file:
            email_content = file.read()
            print(f"Successfully read file: {file_path}")  
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return results
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return results

    
    analyzer = EmailAnalyzer(email_content)

    
    if args.ips:
        analyzer.extract_ips()
        print(f"\nResults for {file_path} (IP addresses):")  
        analyzer.display_results()  
    if args.urls:
        analyzer.extract_urls()
        print(f"\nResults for {file_path} (URLs):")  
        analyzer.display_results()  
    if not args.ips and not args.urls:
        analyzer.run_all()
        print(f"\nResults for {file_path} (All):")  
        analyzer.display_results()  

    return results

def main():
    parser = argparse.ArgumentParser(description="Email Fork: A tool for analyzing emails.")
    parser.add_argument("path", help="Path to the .eml file or a folder containing .eml files")
    parser.add_argument("-p", "--ips", action="store_true", help="Extract IP addresses and their details")
    parser.add_argument("-r", "--urls", action="store_true", help="Extract URLs")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads to use for processing")
    
    args = parser.parse_args()

    # a file or a directory
    if os.path.isfile(args.path):
        
        print(f"Processing single file: {args.path}")  
        results = process_file(args.path, args)
        print(results)  
    elif os.path.isdir(args.path):
        
        print(f"Processing folder: {args.path}")  
        results = {}
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {}
            for filename in os.listdir(args.path):
                if filename.endswith(".eml"):
                    file_path = os.path.join(args.path, filename)
                    print(f"\nProcessing {filename}...\n")
                    futures[executor.submit(process_file, file_path, args)] = filename

            # Collect results as they complete
            for future in as_completed(futures):
                filename = futures[future]
                try:
                    result = future.result()
                    results[filename] = result  
                except Exception as e:
                    print(f"{filename} generated an exception: {e}")
        
        # Print all results 
        print("\nAll Results:")
        for filename, result in results.items():
            print(f"{filename}")
    else:
        print(f"Invalid path: {args.path}. Please provide a valid file or folder.")

if __name__ == "__main__":
    main()