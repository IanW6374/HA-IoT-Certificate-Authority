/* Read-only kernel synchronization status, using the target libc's timex ABI.
 * modes=0 never adjusts time and requires no CAP_SYS_TIME. */
#include <stdio.h>
#include <sys/timex.h>
int main(void) {
    struct timex state = {0};
    int result = adjtimex(&state);
    if (result < 0) return 1;
    printf("{\"result\":%d,\"status\":%d,\"maxerror\":%ld}\n",
           result, state.status, (long)state.maxerror);
    return 0;
}
