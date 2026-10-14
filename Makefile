#########################
######  STRUCTURE  ######
#########################

SRC_DIR         =   sources
INC_DIR         =   includes

BUILD_DIR       =   build
OBJ_DIR         =   ${BUILD_DIR}/obj
DEP_DIR         =   ${BUILD_DIR}/dep

#######################
######  SOURCES  ######
#######################

SRCS            =   main.c AESEncrypt.c AESDecrypt.c AESFunctions.c

###########################
######  COMPILATION  ######
###########################

MAKE            =   make
MAKEFLAGS       +=  --no-print-directory
RED             =   $(shell tput setaf 1)
GREEN           =   $(shell tput setaf 2)
CYAN            =   $(shell tput setaf 6)
RESET           =   $(shell tput setaf 255)

OBJS            =   ${SRCS:%.c=${OBJ_DIR}/%.o}
DEPS            =   ${SRCS:%.c=${DEP_DIR}/%.d}

CC              =   gcc

CFLAGS          =   -Wall -Wextra -Werror -g3 -MMD -MP

MKDIR           =   @mkdir -vp
RM              =   @rm -vrf

NAME            =   AES

#####################
######  RULES  ######
#####################

all: $(NAME)

-include $(DEPS)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

${OBJ_DIR}/%.o: ${SRC_DIR}/%.c
	$(MKDIR) $(dir $@) $(dir $(DEP_DIR)/$*.d)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@ -MF $(DEP_DIR)/$*.d

clean:
	$(RM) $(BUILD_DIR)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re