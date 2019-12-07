package t::Common;

my $pwd = cwd();

use Test::Nginx::Socket -Base;
use Cwd qw(cwd);

my $http_config_default = qq{
    lua_package_path "$pwd/resty_modules/lualib/?.lua;$pwd/lib/?.lua;;";
    lua_package_cpath "$pwd/resty_modules/lualib/?.so;;";
};

add_block_preprocessor(sub {
    my $block = shift;

    $block->set_value("http_config", $http_config_default . ($block->http_config || ''));
    if (!defined $block->no_error_log) {
        $block->set_value("no_error_log", "[error]");
    }
    if (!defined $block->error_code) {
        $block->set_value("error_code", "200");
    }
});
