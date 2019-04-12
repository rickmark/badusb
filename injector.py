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

    def right_byte(self, offset, length):
        return offset <= self.byte < offset + length

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
        pre = data[:self.byte - offset]                         # if we want to replace
        injecting = self.read(offset, length)[:length - len(pre)]
        post = data[len(pre) + len(injecting):length]
        modified = "%s%s%s" % (pre, injecting, post)
        return modified


class PartitionReplaceInject(BaseInject):
    def __init__(self, *args, **kwargs):
        self.initial_num_gpts = len(gpt.READS)
        self.part = None
        super(PartitionReplaceInject, self).__init__(*args, **kwargs)

    @property
    def gpt(self):
        if len(gpt.READS) == self.initial_num_gpts:
            return None
        else:
            return gpt.READS[self.initial_num_gpts]

    def right_byte(self, offset, length):
        if self.gpt:
            self.part = self.gpt.get(self.trigger('partition'))

        if self.part and self.part.first_byte <= offset < self.part.last_byte:
            # Increment the counter if we're reading the first byte of the partition
            if offset <= self.part.first_byte < offset + length:
                self.trigger['count'] += 1
            return True
        else:
            return False

    @property
    def triggered(self):
        return self.trigger['count'] > self.trigger['value']

    def modify(self, offset, length, data):
        self.replace['start'] = offset - self.part.first_byte
        with open(self.replace['filename'], 'r') as fh:
            fh.seek(offset - self.part.first_byte)
            modified = fh.read(length)
        if len(modified) < length:
            modified += data[len(modified):]
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


INJECT_TYPES = {
        "partition_replace": PartitionReplaceInject,
        "byte_read_count": ByteTriggerInject
    }


class Injector(object):
    """Handles injecting data"""
    def __init__(self, injections):
        self.injects = {}
        for inject in injections:
            self.add_inject(**inject)

    def add_inject(self, path, replace, trigger):
        """Add an injection config"""
        if path not in self.injects:
            self.injects[path] = []
        inject_type = INJECT_TYPES.get(trigger['type'])
        self.injects[path].append(inject_type(replace, trigger))

    def get_injects(self, path, length, offset):
        same_path = self.injects.get(path, [])
        if not same_path:
            return same_path
        same_byte = [i for i in same_path if i.right_byte(offset, length)]
        if not same_byte:
            return same_byte
        return [i for i in same_byte if i.triggered]

    def handle(self, path, length, offset, data):
        injects = self.get_injects(path, length, offset)
        for inject in injects:
            data = inject.modify(offset, length, data)
            print("Modifying data using injector %s" % repr(inject))
        return data


def init_injector(args):
    global INJECTOR
    with open(args.config) as fh:
        config = json.load(fh)
    INJECTOR = Injector(config.get('modifiers', []))


def inject(path, length, offset, data):
    return INJECTOR.handle(path, length, offset, data)