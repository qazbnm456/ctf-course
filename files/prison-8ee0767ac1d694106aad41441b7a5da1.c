#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

typedef struct prisoner_s {
  const char *risk;
  char *name;
  char *aka;
  uint32_t age;
  uint32_t cell;
  char *sentence;
  uint32_t note_size;
  char *note;
  struct prisoner_s *next;
} Prisoner;

static Prisoner *head = NULL;

uint8_t occupied = 0;

uint32_t read_until(int32_t fd, char term, char *out, uint32_t max)
{
  uint32_t count = 0;
  char input;

  while (read(fd, &input, 1) == 1 &&
      input != term &&
      count < max) {
    out[count] = input;
    count++;
  }

  out[count] = '\0';
  return count;
}

void init()
{
  Prisoner *curr = NULL;
  int32_t fd = -1;
  uint32_t counter = 0;

  char buffer[128] = {0};
  char *iter = NULL;
  char *ptr = NULL;

  fd = open("prisoner", S_IRUSR);
  if (fd < 0)
    abort();

  while (read_until(fd, '\n', buffer, sizeof(buffer))) {
    head = (Prisoner*)calloc(1, sizeof(Prisoner));
    if (!head)
      abort();

    head->next = curr;
    curr = head;

    iter = buffer;
    if ((ptr = strchr(iter, ':')))
      *ptr = '\0';

    asprintf(&curr->name, "%s", iter);

    iter = ptr + 1;
    if ((ptr = strchr(iter, ':')))
      *ptr = '\0';

    asprintf(&curr->aka, "%s", iter);

    iter = ptr + 1;
    if ((ptr = strchr(iter, ':')))
      *ptr = '\0';

    curr->age = atoi(iter);

    iter = ptr + 1;

    asprintf(&curr->sentence, "%s", iter);

    curr->cell = counter;
    curr->risk = "High";
    counter++;
  }

  close(fd);

  return;
}

void help()
{
  puts("Available commands:");
  puts("help - shows this help");
  puts("list - lists all prisoner");
  puts("note - add a note to a prisoner");
  puts("punish - put a prisoner into the bunker");
  puts("exit - leave");
  fflush(stdout);
}

void list()
{
  Prisoner *iter = head;
  while (iter) {
    printf("Prisoner: %s (%s)\n" \
        "Risk: %s\n" \
        "Age: %d\n" \
        "Cell: %d\n" \
        "Sentence: %s\n",
        iter->name ? iter->name : "",
        iter->aka ? iter->aka : "",
        iter->risk ? iter->risk : "",
        iter->age,
        iter->cell,
        iter->sentence ? iter->sentence : "");
    fflush(stdout);

    write(1, "Note: ", 6);
    write(1, iter->note, iter->note_size);

    puts("\n");
    fflush(stdout);

    iter = iter->next;
  }
}

void note()
{
  char buf[8] = {0};
  uint32_t cell = -1, size = -1;

  write(1, "Cell: ", 6);
  read(0, buf, sizeof(buf)-1);

  cell = atoi(buf);

  Prisoner *iter = head;
  while (iter) {
    if (iter->cell == cell)
      break;

    iter = iter->next;
  }

  if (!iter)
    abort();

  write(1, "Size: ", 6);
  bzero(buf, sizeof(buf));
  read(0, buf, sizeof(buf)-1);

  size = atoi(buf);

  if (size > iter->note_size && iter->note_size != 0) {
    iter->note = (char*)realloc(iter->note, size);

    if (!iter->note)
      abort();

    iter->note_size = size;
  } else if (iter->note_size == 0) {
    iter->note = (char*)malloc(size);

    if (!iter->note)
      abort();

    iter->note_size = size;
  }

  write(1, "Note: ", 6);

  read(0, iter->note, size);

  return;
}

void punish()
{
  char buf[8];
  uint32_t cell = -1;

  if (occupied) {
    write(1, "bunker is occupied\n", 19);
    return;
  }

  write(1, "Cell: ", 6);
  read(0, buf, sizeof(buf)-1);

  cell = atoi(buf);
  Prisoner *iter = head;
  while (iter) {
    if (iter->cell == cell)
      break;

    iter = iter->next;
  }

  if (!iter)
    return;

  free(iter);
  occupied = 1;

  return;
}

void interact()
{
  char cmd[8] = {0};

  write(1, "> ", 2);

  read(0, cmd, sizeof(cmd)-1);

  if (!strncmp(cmd, "help", 4)) {
    help();
  } else if (!strncmp(cmd, "list", 4)) {
    list();
  } else if (!strncmp(cmd, "note", 4)) {
    note();
  } else if (!strncmp(cmd, "punish", 6)) {
    punish();
  } else if (!strncmp(cmd, "\n", 1)) {
    // ignore
  } else if (!strncmp(cmd, "exit", 4)) {
    exit(0);
  }
}

int32_t main()
{
  alarm(60);
  init();
  while (1) {
    interact();
  }
}
