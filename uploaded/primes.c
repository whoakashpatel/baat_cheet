#include "kernel/types.h"
#include "user/user.h"

void sieve(int pfd[])
{
  close(pfd[1]); // close write end
  int prime;
  if (read(pfd[0], &prime, sizeof(int)) == 0) {
    close(pfd[0]);
    exit();
  }

  printf("prime %d\n", prime);

  int n;
  int newpipe[2];
  pipe(newpipe);

  if (fork() == 0) {
    // Child filters remaining numbers
    sieve(newpipe);
  } else {
    close(newpipe[0]);
    while (read(pfd[0], &n, sizeof(int)) > 0) {
      if (n % prime != 0) {
        write(newpipe[1], &n, sizeof(int));
      }
    }
    close(pfd[0]);
    close(newpipe[1]);
    wait(0);
  }
  exit();
}

int main(int argc, char *argv[])
{
  int p[2];
  pipe(p);

  if (fork() == 0) {
    sieve(p);
  } else {
    close(p[0]);
    for (int i = 2; i <= 35; i++) {
      write(p[1], &i, sizeof(int));
    }
    close(p[1]);
    wait(0);
  }
  exit();
}
