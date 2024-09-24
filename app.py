import os
import json
import socket
import zipfile
from uuid import uuid4
from random import choices
from threading import Timer
from Crypto.Cipher import AES
from string import ascii_uppercase
from Crypto.Util.Padding import pad, unpad
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_from_directory,
    flash,
    session,
)

app = Flask(__name__)
app.secret_key = "piyush@11"
app.config["MAX_ATTEMPTS"] = 3
app.config["FILE_DELETION_TIME"] = 10  # Seconds
app.config["ENCRYPTED_FOLDER"] = "encrypted"
TEMPDIR = "temp"


# Utility functions
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = "Unable to get IP address"
    finally:
        s.close()
    return ip_address


BASE_URL = "https://q93659v0-5000.inc1.devtunnels.ms"  # f"http://{get_local_ip()}:5000"


def generate_key():
    return "-".join(["".join(choices(ascii_uppercase, k=3)) for _ in range(3)])


def get_aes_key(key):
    return key.replace("-", "").encode()[:16].ljust(16, b"\0")


def delete_files(*args):
    for file in args:
        if os.path.exists(file):
            os.remove(file)
            print(f"File deleted: {file}")


def get_json_file():
    with open("files.json", "r") as f:
        return json.load(f)


def update_json_file(updated_data):
    with open("files.json", "w") as fw:
        json.dump(updated_data, fw, indent=4)


# Routes
@app.route("/")
def index():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    files = request.files.getlist("files")

    if not files or all(f.filename == "" for f in files):
        return redirect(request.url)

    filename = str(uuid4())
    filepath = os.path.join(TEMPDIR, filename)

    if len(files) == 1:
        file = files[0]
        file.save(filepath)
        ori_name = file.filename

    else:
        with zipfile.ZipFile(filepath, "w") as zipf:
            for file in files:
                _filename = file.filename
                file.save(os.path.join(TEMPDIR, _filename))
                zipf.write(os.path.join(TEMPDIR, _filename), _filename)

        ori_name = f"{filename}.zip"
        for file in files:
            delete_files(os.path.join(TEMPDIR, file.filename))

    jsonfiles = get_json_file()
    jsonfiles.update({filename: ori_name})
    update_json_file(jsonfiles)

    key = generate_key()
    aes_key = get_aes_key(key)
    cipher = AES.new(aes_key, AES.MODE_CBC)

    with open(filepath, "rb") as f:
        file_data = f.read()

    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    encrypted_filepath = os.path.join(app.config["ENCRYPTED_FOLDER"], filename)
    with open(encrypted_filepath, "wb") as ef:
        ef.write(cipher.iv)
        ef.write(encrypted_data)

    session["attempts"] = 0
    delete_files(filepath)

    download_url = f"{BASE_URL}/download/{filename}"

    return render_template(
        "key_display.html",
        key=key,
        download_link=download_url,
    )


@app.route("/download/<filename>", methods=["GET", "POST"])
def download_page(filename):
    user_key = request.args.get("key") or (
        request.form.get("key") if request.method == "POST" else None
    )

    if str(user_key).startswith("Download"):
        user_key = str(user_key).split(" ")[-1]

    attempts = session.get("attempts", 0)
    encrypted_filepath = os.path.join(app.config["ENCRYPTED_FOLDER"], filename)

    if user_key:
        try:
            with open(encrypted_filepath, "rb") as ef:
                iv = ef.read(16)
                encrypted_data = ef.read()

            aes_key = get_aes_key(user_key)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

            decrypted_filepath = os.path.join(TEMPDIR, filename)
            with open(decrypted_filepath, "wb") as df:
                df.write(decrypted_data)

            return render_template("success.html", filename=filename)

        except Exception as e:
            print(e)
            attempts += 1
            session["attempts"] = attempts

            if attempts >= app.config["MAX_ATTEMPTS"]:
                jsonfiles = get_json_file()
                jsonfiles.pop(filename, None)
                update_json_file(jsonfiles)

                delete_files(encrypted_filepath)
                return render_template("deleted.html", filename=filename)

            flash(
                f"Invalid key. You have {app.config['MAX_ATTEMPTS'] - attempts} attempts left."
            )

    return render_template("download.html", filename=filename)


@app.route("/dir/<path:filename>")
def temp_file(filename):
    jsonfiles = get_json_file()
    ori_filename = jsonfiles[filename]
    jsonfiles.pop(filename, None)
    update_json_file(jsonfiles)

    encrypted_filepath = os.path.join(app.config["ENCRYPTED_FOLDER"], filename)
    decrypted_filepath = os.path.join(TEMPDIR, filename)

    bg = Timer(
        app.config["FILE_DELETION_TIME"],
        delete_files,
        args=(
            encrypted_filepath,
            decrypted_filepath,
        ),
    )
    bg.start()

    return send_from_directory(
        TEMPDIR, filename, as_attachment=True, download_name=ori_filename
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
