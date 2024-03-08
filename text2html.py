import os
import argparse
from datetime import datetime

def write_summary_section(report_file):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file.write(f"# Summary Recon Report\n\n")
    report_file.write(f"Generated on {current_time}\n\n")

def process_files(folder, report_file):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            if filename.endswith('.txt'):
                file_path = os.path.join(root, filename)
                with open(file_path, 'r', encoding='latin-1') as content_file:
                    content = content_file.read()
                    report_file.write(f"## {filename}\n")
                    report_file.write("<pre>\n")
                    report_file.write(f"{content}\n")
                    report_file.write("</pre>\n\n")

def create_markdown_report(input_folder, output_file):
    with open(output_file, 'w', encoding='utf-8') as report_file:
        write_summary_section(report_file)
        process_files(input_folder, report_file)

def main():
    parser = argparse.ArgumentParser(description="Generate Markdown report from text files.")
    parser.add_argument("-i", "--input-folder", required=True, help="Path to the folder containing text files.")
    parser.add_argument("-o", "--output-file", required=True, help="Path to the output Markdown file.")
    args = parser.parse_args()

    if not os.path.exists(args.input_folder):
        print(f"Error: Input folder '{args.input_folder}' not found.")
        return

    create_markdown_report(args.input_folder, args.output_file)

if __name__ == "__main__":
    main()
