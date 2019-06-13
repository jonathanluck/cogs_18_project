import EncryptedArchive as ea
import os
import shutil

def test_the_thing():
    arch = ea.EncryptedArchive()
    files = [os.path.join("test_files",f) for f in os.listdir("test_files")]
    files_bn = list(map(os.path.basename, files))
    arch.create_archive("test_password_thing", "test_archive.out", files)

    arch.load_archive("test_password_thing", "test_archive.out")

    #make sure all the file names are in tact
    assert(sorted(arch.file_names) == sorted(files_bn))

    #make sure all the file data is still in tact.
    for fn in files_bn:
        arch.extract_file(fn)
        orig_data = open(os.path.join("test_files",fn), 'rb').read()
        unarch_data = open(fn,'rb').read()
        assert unarch_data == orig_data
        os.remove(fn)

    #make sure we fail on wrong password
    failed_load = False
    try:
        arch = ea.EncryptedArchive()
        arch.load_archive("wrong_password", "test_archive.out")
    except ValueError:
        failed_load = True

    assert failed_load

    #tamper with the file and make sure that it is still failing to load
    out_file = open("test_archive_bad.out",'wb')
    orig_archive_data = open("test_archive.out", 'rb').read()
    mod_archive_data = b'asdf' + orig_archive_data[4:]
    out_file.write(mod_archive_data)
    out_file.close()
    failed_load_2 = False
    try:
        arch = ea.EncryptedArchive()
        arch.load_archive("test_password_thing", "test_archive_bad.out")
    except ValueError:
        failed_load_2 = True

    assert failed_load_2
    os.remove("test_archive.out")
    os.remove("test_archive_bad.out")
    print("Wao all the tests passed. I did a good job writing codes")
