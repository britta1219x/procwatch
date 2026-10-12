#include <stdio.h>
#include "../src/path_rules.h"

struct test_case {
    const char *path;
    unsigned char expected;
};

int main(void)
{
    const struct test_case cases[] = {
        { "/etc/passwd", ALERT_PASSWD },
        { "/etc/passwd.bak", ALERT_NONE },
        { "/etc/shadow", ALERT_SHADOW },
        { "/etc/shadow-old", ALERT_NONE },
        { "/etc/sudoers", ALERT_SUDOERS },
        { "/etc/sudoers.bak", ALERT_NONE },
        { "/etc/sudoers.d/custom", ALERT_NONE },
        { "/home/alice/.ssh/id_rsa", ALERT_SSHKEY },
        { "/home/alice/.ssh/", ALERT_SSHKEY },
        { "/home/alice/.ssh", ALERT_NONE },
        { "etc/passwd", ALERT_NONE },
        { "/tmp/ordinary", ALERT_NONE },
    };

    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char buf[MAX_PATH_LEN] = {};
        unsigned char actual;

        snprintf(buf, sizeof(buf), "%s", cases[i].path);
        actual = classify_path(buf);
        if (actual != cases[i].expected) {
            fprintf(stderr, "case %u failed: %s => %u (expected %u)\n",
                    i, cases[i].path, actual, cases[i].expected);
            return 1;
        }
    }

    puts("path rules: 12 cases passed");
    return 0;
}
