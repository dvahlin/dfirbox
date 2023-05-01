import os
import difflib
import re
import logging
import hashlib
from chardet.universaldetector import UniversalDetector
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = "no_secret_here_O.O"

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/helpful-scripts')
def helpful_scripts():
    return render_template('helpful_scripts.html')

@app.errorhandler(Exception)
def handle_exception(e):
    """Return JSON instead of HTML for all errors"""
    response = {
        'error': str(e)
    }
    return jsonify(response), 500


@app.route("/compare-files", methods=["GET", "POST"])
def compare_files():
    if request.method == "POST":
        file1 = request.files.get("file1")
        file2 = request.files.get("file2")
        if not file1 or not file2:
            flash("Please upload exactly two files.", "error")
            return redirect(request.url)

        file_contents = []
        for file in [file1, file2]:
            filename = secure_filename(file.filename)
            file_contents.append(file.read().decode("utf-8", errors="ignore"))

        diff = list(difflib.unified_diff(file_contents[0].splitlines(), file_contents[1].splitlines()))

        return render_template("result_compare_files.html", diff=diff)

    return render_template("compare_files.html")

@app.route('/compare-file-list', methods=['GET', 'POST'])
def compare_file_list():
    if request.method == 'POST':
        file1 = request.files.get('file1')
        file2 = request.files.get('file2')

        if not file1 or not file2:
            flash('Both files are required', 'error')
            return redirect(url_for('compare_file_list'))

        file_contents1 = file1.read().decode('utf-8').splitlines()
        file_contents2 = file2.read().decode('utf-8').splitlines()

        diff = generate_diff_for_file_lists(file_contents1, file_contents2)

        return render_template("result_compare_file_list.html", diff=diff)

    return render_template("compare_file_list.html")

# Compare files
def generate_diff_for_file_lists(file_list1, file_list2):
    file_list1_filenames = set(os.path.basename(file_path) for file_path in file_list1)
    file_list2_filenames = set(os.path.basename(file_path) for file_path in file_list2)

    not_matching = file_list2_filenames - file_list1_filenames

    return {
        'not_matching': list(not_matching),
    }

@app.route('/compare-file-hashes', methods=['GET', 'POST'])
def compare_file_hashes():
    if request.method == 'POST':
        file1 = request.files.get('file1')
        file2 = request.files.get('file2')

        if not file1 or not file2:
            flash('Both files are required', 'error')
            return redirect(url_for('compare_file_hashes'))

        file_contents1 = file1.read().decode('utf-8').splitlines()
        file_contents2 = file2.read().decode('utf-8').splitlines()

        hash_mismatch = generate_hash_mismatch(file_contents1, file_contents2)

        return render_template("result_compare_file_hashes.html", hash_mismatch=hash_mismatch)

    return render_template("compare_file_hashes.html")



def generate_hash_mismatch(file_list1, file_list2):
    file_list1_dict = {os.path.basename(line.split(' ', 1)[1].strip()): line.split(' ', 1)[0] for line in file_list1}
    file_list2_dict = {os.path.basename(line.split(' ', 1)[1].strip()): line.split(' ', 1)[0] for line in file_list2}

    hash_mismatch = []

    for file_name, file_hash in file_list2_dict.items():
        if file_name in file_list1_dict:
            file1_hash = file_list1_dict[file_name]
            file2_hash = file_hash

            if file1_hash != file2_hash:
                hash_mismatch.append((file_name, file1_hash, file2_hash))

    return hash_mismatch


@app.route('/upload-ldif', methods=['GET', 'POST'])
def upload_ldif():
    if request.method == 'POST':
        ldif_file1 = request.files.get('ldif_file1')
        ldif_file2 = request.files.get('ldif_file2')

        if not ldif_file1 or not ldif_file2:
            flash('Both LDIF files are required', 'error')
            return redirect(url_for('upload_ldif'))

        # Detect encoding for ldif_file1
        detector = UniversalDetector()
        for line in ldif_file1:
            detector.feed(line)
            if detector.done:
                break
        detector.close()
        ldif_file1.seek(0)  # Reset the file pointer to the beginning
        encoding1 = detector.result['encoding']
        ldif_data1 = ldif_file1.read().decode(encoding1)

        # Detect encoding for ldif_file2
        detector.reset()
        for line in ldif_file2:
            detector.feed(line)
            if detector.done:
                break
        detector.close()
        ldif_file2.seek(0)  # Reset the file pointer to the beginning
        encoding2 = detector.result['encoding']
        ldif_data2 = ldif_file2.read().decode(encoding2)

        # Call the LDIF comparison function with the ldif_data1 and ldif_data2
        comparison_result = compare_ldif(ldif_data1, ldif_data2)

        # Render the result_ldif.html template with the comparison result
        #return render_template('result_ldif.html', added_attributes=comparison_result['added_attributes'], removed_attributes=comparison_result['removed_attributes'])
        return render_template('result_ldif.html', added_entries=comparison_result['added_entries'], removed_entries=comparison_result['removed_entries'])

    # Render the upload_ldif.html template for GET requests or if there was an error
    return render_template('upload_ldif.html')


def parse_ldif(ldif_data):
    entries = {}
    current_dn = None
    current_entry = None

    for line in ldif_data.splitlines():
        if line.startswith(" "):
            line = line[1:]
        if not line.strip():
            continue
        if line.startswith("#"):
            continue

        parts = line.split(":", 1)
        attr = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""

        if attr.lower() == "dn":
            if current_dn:
                entries[current_dn] = current_entry
            current_dn = value
            current_entry = {}
        else:
            current_entry[attr] = current_entry.get(attr, set())
            current_entry[attr].add(value)

    if current_dn:
        entries[current_dn] = current_entry

    return entries

def compare_ldif(ldif_data1, ldif_data2):
    parsed_data1 = parse_ldif(ldif_data1)
    parsed_data2 = parse_ldif(ldif_data2)
    added_entries = []
    removed_entries = []

    for dn, entry1 in parsed_data1.items():
        entry2 = parsed_data2.get(dn)

        if not entry2:
            print(f"Missing entry in ldif_data2: {dn}")
            removed_entries.append({'dn': dn, 'attributes': entry1})
            continue

        added_attributes = {}
        removed_attributes = {}
        for attr, values1 in entry1.items():
            values2 = entry2.get(attr, set())

            added_values = values1 - values2
            removed_values = values2 - values1

            if added_values:
                added_attributes[attr] = added_values
            if removed_values:
                removed_attributes[attr] = removed_values

        if added_attributes:
            print(f"Added entry: {dn}, attributes: {added_attributes}")
            added_entries.append({'dn': dn, 'attributes': added_attributes})
        if removed_attributes:
            print(f"Removed entry: {dn}, attributes: {removed_attributes}")
            removed_entries.append({'dn': dn, 'attributes': removed_attributes})

    # Compare entry2 with entry1
    for dn, entry2 in parsed_data2.items():
        if dn not in parsed_data1:
            print(f"Added entry not in ldif_data1: {dn}")
            added_entries.append({'dn': dn, 'attributes': entry2})
        else:
            entry1 = parsed_data1[dn]
            for attr, values2 in entry2.items():
                values1 = entry1.get(attr, set())

                added_values = values2 - values1
                removed_values = values1 - values2

                if added_values:
                    print(f"Missing values for attribute '{attr}' in entry '{dn}' in ldif_data1: {added_values}") 
                    added_entries.append({'dn': dn, 'attribute': attr, 'values': added_values})
                if removed_values:
                    print(f"Missing values for attribute '{attr}' in entry '{dn}' in ldif_data2: {removed_values}")
                    removed_entries.append({'dn': dn, 'attribute': attr, 'values': removed_values})

    return {
        'added_entries': added_entries,
        'removed_entries': removed_entries
    }

if __name__ == "__main__":
    app.run(debug=True)
