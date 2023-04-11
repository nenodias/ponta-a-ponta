
def load_pem_file(name):
    with open(name, 'rb') as f:
        content = f.read()
    return content
