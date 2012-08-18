/^#include/	{ sub("#","~")}
/^#define/	{ sub("#","~")}
		{ if (NF > 0) print}
