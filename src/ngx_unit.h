
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NGX_UNIT_H_INCLUDED_
#define _NGX_UNIT_H_INCLUDED_


/* clang */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>


#define nxt_inline     static inline __attribute__((always_inline))

typedef int  nxt_err_t;


#define                                                                       \
nxt_max(val1, val2)                                                           \
    ((val1 < val2) ? (val2) : (val1))


#define                                                                       \
nxt_memzero(buf, length)                                                      \
    (void) memset(buf, 0, length)


#define nxt_is_power_of_two(value)                                            \
    ((((value) - 1) & (value)) == 0)


#define                                                                       \
nxt_align_size(d, a)                                                          \
    (((d) + ((size_t) (a) - 1)) & ~((size_t) (a) - 1))


#define                                                                       \
nxt_container_of(p, type, field)                                              \
    (type *) ((u_char *) (p) - offsetof(type, field))


#define NXT_MAX_ALIGNMENT  16


/* malloc */
void *nxt_malloc(size_t size);
void *nxt_zalloc(size_t size);
void *nxt_memalign(size_t alignment, size_t size);

#define                                                                       \
nxt_free(p)                                                                   \
    free(p)


/* queue */
typedef struct nxt_queue_link_s  nxt_queue_link_t;

struct nxt_queue_link_s {
    nxt_queue_link_t  *prev;
    nxt_queue_link_t  *next;
};


typedef struct {
    nxt_queue_link_t  head;
} nxt_queue_t;


#define                                                                       \
nxt_queue_init(queue)                                                         \
    do {                                                                      \
        (queue)->head.prev = &(queue)->head;                                  \
        (queue)->head.next = &(queue)->head;                                  \
    } while (0)


#define                                                                       \
nxt_queue_sentinel(link)                                                      \
    do {                                                                      \
        (link)->prev = (link);                                                \
        (link)->next = (link);                                                \
    } while (0)


/*
 * Short-circuit a queue link to itself to allow once remove safely it
 * using nxt_queue_remove().
 */

#define                                                                       \
nxt_queue_self(link)                                                          \
    nxt_queue_sentinel(link)


#define                                                                       \
nxt_queue_is_empty(queue)                                                     \
    (&(queue)->head == (queue)->head.prev)

/*
 * A loop to iterate all queue links starting from head:
 *
 *      nxt_queue_link_t  link;
 *  } nxt_type_t  *tp;
 *
 *
 *  for (lnk = nxt_queue_first(queue);
 *       lnk != nxt_queue_tail(queue);
 *       lnk = nxt_queue_next(lnk))
 *  {
 *      tp = nxt_queue_link_data(lnk, nxt_type_t, link);
 *
 * or starting from tail:
 *
 *  for (lnk = nxt_queue_last(queue);
 *       lnk != nxt_queue_head(queue);
 *       lnk = nxt_queue_prev(lnk))
 *  {
 *      tp = nxt_queue_link_data(lnk, nxt_type_t, link);
 */

#define                                                                       \
nxt_queue_first(queue)                                                        \
    (queue)->head.next


#define                                                                       \
nxt_queue_last(queue)                                                         \
    (queue)->head.prev


#define                                                                       \
nxt_queue_head(queue)                                                         \
    (&(queue)->head)


#define                                                                       \
nxt_queue_tail(queue)                                                         \
    (&(queue)->head)


#define                                                                       \
nxt_queue_next(link)                                                          \
    (link)->next


#define                                                                       \
nxt_queue_prev(link)                                                          \
    (link)->prev


#define                                                                       \
nxt_queue_insert_head(queue, link)                                            \
    do {                                                                      \
        (link)->next = (queue)->head.next;                                    \
        (link)->next->prev = (link);                                          \
        (link)->prev = &(queue)->head;                                        \
        (queue)->head.next = (link);                                          \
    } while (0)


#define                                                                       \
nxt_queue_insert_tail(queue, link)                                            \
    do {                                                                      \
        (link)->prev = (queue)->head.prev;                                    \
        (link)->prev->next = (link);                                          \
        (link)->next = &(queue)->head;                                        \
        (queue)->head.prev = (link);                                          \
    } while (0)


#define                                                                       \
nxt_queue_insert_after(target, link)                                          \
    do {                                                                      \
        (link)->next = (target)->next;                                        \
        (link)->next->prev = (link);                                          \
        (link)->prev = (target);                                              \
        (target)->next = (link);                                              \
    } while (0)


#define                                                                       \
nxt_queue_insert_before(target, link)                                         \
    do {                                                                      \
        (link)->next = (target);                                              \
        (link)->prev = (target)->prev;                                        \
        (target)->prev = (link);                                              \
        (link)->prev->next = (link);                                          \
    } while (0)


#define                                                                       \
nxt_queue_remove(link)                                                        \
    do {                                                                      \
        (link)->next->prev = (link)->prev;                                    \
        (link)->prev->next = (link)->next;                                    \
    } while (0)


/*
 * Add the queue "tail" to the queue "queue".
 * If the queue "tail" is intended to be reused again,
 * it must be initiated with nxt_queue_init(tail).
 */

#define                                                                       \
nxt_queue_add(queue, tail)                                                    \
    do {                                                                      \
        (queue)->head.prev->next = (tail)->head.next;                         \
        (tail)->head.next->prev = (queue)->head.prev;                         \
        (queue)->head.prev = (tail)->head.prev;                               \
        (queue)->head.prev->next = &(queue)->head;                            \
    } while (0)


#define                                                                       \
nxt_queue_link_data(lnk, type, link)                                          \
    nxt_container_of(lnk, type, link)


#define nxt_queue_each(elt, queue, type, link)                                \
    do {                                                                      \
        nxt_queue_link_t  *_lnk, *_nxt;                                       \
                                                                              \
        for (_lnk = nxt_queue_first(queue);                                   \
             _lnk != nxt_queue_tail(queue);                                   \
             _lnk = _nxt) {                                                   \
                                                                              \
            _nxt = nxt_queue_next(_lnk);                                      \
            elt = nxt_queue_link_data(_lnk, type, link);                      \

#define nxt_queue_loop                                                        \
        }                                                                     \
    } while(0)


/* rbtree */
typedef struct nxt_rbtree_node_s  nxt_rbtree_node_t;

struct nxt_rbtree_node_s {
    nxt_rbtree_node_t         *left;
    nxt_rbtree_node_t         *right;
    nxt_rbtree_node_t         *parent;

    uint8_t                   color;
};


typedef struct {
    nxt_rbtree_node_t         *left;
    nxt_rbtree_node_t         *right;
    nxt_rbtree_node_t         *parent;
} nxt_rbtree_part_t;


#define NXT_RBTREE_NODE(node)                                                 \
    nxt_rbtree_part_t         node;                                           \
    uint8_t                   node##_color


#define NXT_RBTREE_NODE_INIT  { NULL, NULL, NULL }, 0


typedef struct {
    nxt_rbtree_node_t         sentinel;
} nxt_rbtree_t;


/*
 * A comparison function should return intptr_t result because
 * this eliminates overhead required to implement correct addresses
 * comparison without result truncation.
 */
typedef intptr_t (*nxt_rbtree_compare_t)(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);


#define nxt_rbtree_root(tree)                                                 \
    ((tree)->sentinel.left)


#define nxt_rbtree_sentinel(tree)                                             \
    (&(tree)->sentinel)


#define nxt_rbtree_is_empty(tree)                                             \
    (nxt_rbtree_root(tree) == nxt_rbtree_sentinel(tree))


#define nxt_rbtree_min(tree)                                                  \
    nxt_rbtree_branch_min(tree, &(tree)->sentinel)


nxt_inline nxt_rbtree_node_t *
nxt_rbtree_branch_min(nxt_rbtree_t *tree, nxt_rbtree_node_t *node)
{
    while (node->left != nxt_rbtree_sentinel(tree)) {
        node = node->left;
    }

    return node;
}


#define nxt_rbtree_is_there_successor(tree, node)                             \
    ((node) != nxt_rbtree_sentinel(tree))


nxt_inline nxt_rbtree_node_t *
nxt_rbtree_node_successor(nxt_rbtree_t *tree, nxt_rbtree_node_t *node)
{
    nxt_rbtree_node_t  *parent;

    if (node->right != nxt_rbtree_sentinel(tree)) {
        return nxt_rbtree_branch_min(tree, node->right);
    }

    for ( ;; ) {
        parent = node->parent;

        /*
         * Explicit test for a root node is not required here, because
         * the root node is always the left child of the sentinel.
         */
        if (node == parent->left) {
            return parent;
        }

        node = parent;
    }
}


void nxt_rbtree_init(nxt_rbtree_t *tree, nxt_rbtree_compare_t compare);
void nxt_rbtree_insert(nxt_rbtree_t *tree, nxt_rbtree_part_t *node);
void nxt_rbtree_delete(nxt_rbtree_t *tree, nxt_rbtree_part_t *node);

/*
 * nxt_rbtree_destroy_next() is iterator to use only while rbtree destruction.
 * It deletes a node from rbtree and returns the node.  The rbtree is not
 * rebalanced after deletion.  At the beginning the "next" parameter should
 * be equal to rbtree root.  The iterator should be called in loop until
 * the "next" parameter will be equal to the rbtree sentinel.  No other
 * operations must be performed on the rbtree while destruction.
 */
nxt_rbtree_node_t *nxt_rbtree_destroy_next(nxt_rbtree_t *tree,
    nxt_rbtree_node_t **next);


#endif /* _NGX_UNIT_H_INCLUDED_ */
