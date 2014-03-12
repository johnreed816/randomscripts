#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define MAXV   1000
#define MAXINT 100007
#define FALSE 0x0

int parent[MAXV];   /* discovery relation */

typedef struct {
    int y;                      /* adjacency */
    int weight;                 /* edge weight */
    struct edgenode *next;      /* next edge in list */
} edgenode;

typedef struct {
    edgenode *edges[MAXV+1];    /* adjacency */
    int degree[MAXV+1];         /* degree of each vertex */
    int nvertices;              /* number of vertices in this graph */
    int nedges;                 /* number of edges in this graph */
    int directed;               /* is the graph directed or indirected */
} graph;

void dijkstra(graph *g, int start)
{
    int i;                  /* counter */
    edgenode *p;            /* temporary pointer */
    bool intree[MAXV+1];    /* vertext in the tree yet? */
    int distance[MAXV+1];   /* distance vertex is from the start */
    int v;                  /* current vertex */
    int w;                  /* candidate next vertex */
    int weight;             /* edge weight */
    int dist;               /* best current distance from start */

    for(i = 0; i <= g->nvertices; i++)
    {
        intree[i] = FALSE;
        distance[i] = MAXINT;
        parent[i] = -1;
    }
    distance[start] = 0;
    v = start;
    while(intree[v] == FALSE) 
    {
        intree[v] = TRUE;
        for(i=0;i<g->degree[v];i++)
        {
            w = g->edges[v][i].v;
            weight = g->edges[v][i].weight;
            if(distance[w] > (distance[v]+weight))
            {
                distance[w] = distance[v]+weight;
                parent[w] = v;
            }
        }
        v = 1;
        dist = MAXINT;
        for(i=1;i<=g.nvertices;i++)
        {
            if ((intree[i] == FALSE) && (dist > distance[i])) 
            {
                dist = distance[i];
                v = 1;
            }
        }
    }
}

initialize_graph(graph *g, bool directed)
{
    printf("In initialize graph\n");
    int i;
    g -> nvertices = 0;
    g -> nedges = 0;
    g -> directed = directed;
    for (i=1; i<=MAXV;i++) g->degree[i] = 0;
    for (i=1; i<=MAXV;i++) g->edges[i] = NULL;
    printf("leaving initialize graph\n");
}

insert_edge(graph *g, int x, int y, bool directed)
{
    printf("IN insert edge\n");
    edgenode *p;
    p = malloc(sizeof(edgenode));
    p->weight = NULL;
    p->y = y;
    p->next = g->edges[x];

    g->edges[x] = p;
    g->degree[x] ++;

    if (directed == FALSE)
        insert_edge(g, x, y, 1);
    else
        g->nedges++;
}

read_graph(graph *g, bool directed)
{
    int i;           /* counter */
    int m;           /* number of edges */
    int x, y;        /* vertices in edge (x, y) */

    initialize_graph(g, directed);
    printf("Enter the number of vertices\n");
    scanf("%d %d", &(g->nvertices), &m);
    for(i=1;i<=m;i++) 
    {
        printf("enter the next coordinates: ");
        scanf("%d %d", &x, &y);
        insert_edge(g, x, y, directed);
    }
}

print_graph(graph *g)
{
    int i;
    edgenode *p;

    for(i=1;i<=g->nvertices;i++)
    {
        printf("%d ", i);
        p = g->edges[i];
        while ( p != NULL ) {
            printf(" %d",p->y);
            p = p->next;
        }
        printf("\n");
    }
}

int main()
{
    graph g;
    read_graph(&g, 0);
    dijkstra(&g, 0);
    print_graph(&g);
}
