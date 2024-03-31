#include "include/lib.h"
#include "Router.h"

int main(int argc, char *argv[])
{
	Router *router = new Router(argv[1]);

	init(argc - 2, argv + 2);
	router->run();
	delete router;
}
