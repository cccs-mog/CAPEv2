import functools
import json
import sys
import uuid

from ETW.etw import (
    ProviderInfo,
    GUID,
    TraceProperties,
    EventProvider,
    EventConsumer,
    ERROR_ALREADY_EXISTS,
)


class AMSI:
    def __init__(self, event_callback=None):
        try:
            self.providers = [ProviderInfo("AMSI", GUID("{2A576B87-09A7-520E-C21A-4942F0271D67}"))]
        except OSError as err:
            raise OSError("AMSI not supported on this platform") from err
        self.provider = None
        self.properties = TraceProperties()
        self.session_name = "{:s}".format(str(uuid.uuid4()))
        self.running = False
        self.event_callback = event_callback
        self.trace_logfile = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc, ex, tb):
        self.stop()

    def start(self):
        if self.provider is None:
            self.provider = EventProvider(self.session_name, self.properties, self.providers)

        if not self.running:
            self.running = True
            try:
                self.provider.start()
            except OSError as err:
                if err.winerror != ERROR_ALREADY_EXISTS:
                    raise err

            # Start the consumer
            self.consumer = EventConsumer(
                self.session_name,
                self.event_callback,
            )
            self.consumer.start()

    def stop(self):
        """
        Stops the current consumer and provider.

        :return: Does not return anything.
        """

        if self.provider:
            self.running = False
            self.provider.stop()
            self.consumer.stop()


def jsonldump(obj, fp):
    """Write each event object on its own line."""
    json.dump(obj, fp)
    fp.write("\n")


def main():
    with AMSI(event_callback=functools.partial(jsonldump, fp=sys.stdout)):
        print("Listening for AMSI events. Press enter to stop...")
        sys.stdin.readline()


if __name__ == "__main__":
    main()
