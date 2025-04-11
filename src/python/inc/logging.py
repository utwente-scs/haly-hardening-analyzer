import logging


class CustomFormatter(logging.Formatter):
    grey = "\x1b[37;20m"
    white = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    fmt = "[%(process)d] %(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: grey + fmt + reset,
        logging.INFO: white + fmt + reset,
        logging.WARNING: yellow + fmt + reset,
        logging.ERROR: red + fmt + reset,
        logging.CRITICAL: bold_red + fmt + reset,
    }

    def __init__(self, colored: bool = True):
        super().__init__()
        self.colored = colored

    def format(self, record):
        fmt = self.fmt
        if self.colored:
            fmt = self.FORMATS.get(record.levelno)
        return logging.Formatter(fmt).format(record)
