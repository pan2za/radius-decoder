CC = gcc
ARCHIVER = ar
CFLAGS = -Wall
CFLAGS1 = -I .
OBJDIR = OBJS
LIBDIR = LIBS
LINK_FLAGS = 
LIB = libradius.a
LIB_NAME = $(addprefix $(LIBDIR)/, $(LIB))
SRC_FILES = $(wildcard *.c)
OBJ_FILES = $(patsubst %.c, %.o, $(SRC_FILES))
OBJS = $(addprefix $(OBJDIR)/, $(OBJ_FILES))

$(OBJS): | create

all: $(OBJS)
	@echo "\033[33m"
	@echo "==============================="
	@echo "Building Source files"
	@echo "==============================="
	@echo "\033[0m"
	$(ARCHIVER) -cr $(LIB_NAME) $(OBJS)

.PHONY: create
create: 	
	@mkdir -p $(OBJDIR)
	@mkdir -p $(LIBDIR)


.PHONY: clean
clean:
	@echo "\033[31m"
	@echo "==============================="
	@echo "Removing all files"
	@echo "==============================="
	@echo "\033[0m"
	@rm -rf $(OBJDIR) $(LIBDIR)

$(OBJDIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(CFLAGS1) $< -o $@
