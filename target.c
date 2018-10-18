#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  int i = 0;
  if (argc > 1) {
    printf("Application was called with the following args: ");
    for (int j = 1; j < argc; j++) {
      printf("%s ", argv[j]);
    }
    printf("\n");
  }
  while (1) {
    printf("%d ", i);
    fflush(stdout);
    sleep(1);
    i++;
  }
  return 0;
}
