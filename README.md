# PHP Low-level Crypto

The php-lcrypto is a Low-level wrapper of OpenSSL Crypto library.


## Installation

### Linux

Before starting with installation this extensions, the `OpenSSL` library has to be installed. It is defaultly installed on the most Linux distribution.

Currently PHP needs to be compiled with OpenSSL extension (`--with-openssl`). This dependency will be removed in the future.

#### Manual Installation

First clone the repository
```
git clone --recursive https://github.com/bukka/php-lcrypto.git
```

Then go to the created directory and compile the extension. The PHP development package has to be installed (command `phpize` must be available).
```
cd php-lcrypto
phpize
./configure
make
sudo make install
```

Finally the following line needs to be added to `php.ini`
```
extension=lcrypto.so
```

## API

API documentation will be added once the extension is more developed. For now, the [test directory](tests/) contains some examples how the extension can be used. 

## TODO list

The TODO list can be found [here](TODO.md).

