#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int i = 0;
  while (1) {
    printf("%d ", i);
    fflush(stdout);
    sleep(1);
    i++;
  }
  return 0;
}
