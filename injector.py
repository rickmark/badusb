import json
import gpt

INJECTOR = None


class BaseInject(object):
    def __init__(self, replace, trigger):
        self.replace = replace
        self.trigger = trigger
        self.init_trigger()

    def init_trigger(self):
        pass

    @property
    def triggered(self):
        return True

    @property
    def byte(self):
        return -1

    def read(self, offset, length):
        if self.replace['source'] == 'str':
            return self.replace['value']
        elif self.replace['source'] == 'file':
            with open(self.replace['filename']) as fh:
                fh.seek(self.replace.get('start', offset), 0)
                return fh.read(self.replace.get('length', length))
        elif self.replace('source') == 'cow':
            with open(self.replace['filename']) as fh:
                fh.seek(offset)
                return fh.read(length)
        else:
            return ""

    def modify(self, offset, length, data):
        """Modify the data however we're supposed to"""
        # Let's say we want to replace bytes 5:10 with aaaaaaaaaaaaaaaaaaaaaaaaaaaa, with offset 0, length 20
        # pre should give us 0:5, cool
        # injecting should give us aaaaa..., which we'll want to truncate to 15 bytes (length - len(pre))
        # Post will be nothing in this case
        pre = data[:self.byte - offset]                         # if we want to replace
        injecting = self.read(offset, length)[:length - len(pre)]
        post = data[len(pre) + len(injecting):length]
        modified = "%s%s%s" % (pre, injecting, post)
        return modified


class ByteTriggerInject(BaseInject):
    def init_trigger(self):
        if self.trigger['type'] == 'read_count':
            self.trigger['count'] = 0

    @property
    def triggered(self):
        read_count = self.trigger['count']
        self.trigger['count'] += 1
        return read_count >= self.trigger['value']

    @property
    def byte(self):
        return self.trigger['byte']


class PartitionTriggerInject(ByteTriggerInject):
    def __init__(self, *args, **kwargs):
        self.initial_num_gpts = len(gpt.READS)
        super(PartitionTriggerInject, self).__init__(*args, **kwargs)

    @property
    def byte(self):
        if len(gpt.READS) == self.initial_num_gpts:
            # We haven't read the GPT yet
            return -1
        else:
            part = gpt.READS[self.initial_num_gpts].get(self.trigger['partition'])
            if not part:
                return -1
            # Pick a byte in the middle:
            return (part.first_byte + part.last_byte) / 2


INJECT_TYPES = {
        "partition_read_count": PartitionTriggerInject,
        "byte_read_count": ByteTriggerInject
    }


class Injector(object):
    """Handles injecting data"""
    def __init__(self, injections):
        self.injects = {}
        for inject in injections:
            self.add_inject(**inject)

    def add_inject(self, path, key, replace, trigger):
        """Add an injection config"""
        if path not in self.injects:
            self.injects[path] = []
        inject_type = INJECT_TYPES.get(trigger['type'])
        self.injects[path].append(Inject(key, replace, trigger))

    def get_injects(self, path, length, offset):
        same_path = self.injects.get(path, [])
        if not same_path:
            return same_path
        same_byte = [i for i in same_path if offset <= i.byte < offset+length]
        if not same_byte:
            return same_byte
        return [i for i in same_byte if i.triggered]

    def handle(self, path, length, offset, data):
        injects = self.get_injects(path, length, offset)
        for inject in injects:
            data = inject.modify(offset, length, data)
        return data


def init_injector(args):
    global INJECTOR
    with open(args.config) as fh:
        config = json.load(fh)
    INJECTOR = Injector(config.get('modifiers', []))


def inject(path, length, offset, data):
    return INJECTOR.handle(path, length, offset, data)