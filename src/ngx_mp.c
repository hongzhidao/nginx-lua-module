
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_unit.h>
#include <ngx_mp.h>


/*
 * A memory pool allocates memory in clusters of specified size and aligned
 * to page_alignment.  A cluster is divided on pages of specified size.  Page
 * size must be a power of 2.  A page can be used entirely or can be divided
 * on chunks of equal size.  Chunk size must be a power of 2.  Non-freeable
 * memory is also allocated from pages.  A cluster can contains a mix of pages
 * with different chunk sizes and non-freeable pages.  Cluster size must be
 * a multiple of page size and may be not a power of 2.  Allocations greater
 * than page are allocated outside clusters.  Start addresses and sizes of
 * the clusters and large allocations are stored in rbtree blocks to find
 * them on free operations.  The rbtree nodes are sorted by start addresses.
 * The rbtree is also used to destroy memory pool.
 */


typedef struct {
    /*
     * Used to link
     *  *) pages with free chunks in pool chunk pages lists,
     *  *) pages with free space for non-freeable allocations,
     *  *) free pages in clusters.
     */
    nxt_queue_link_t     link;

    union {
        /* Chunk bitmap.  There can be no more than 32 chunks in a page. */
        uint32_t         map;

        /* Size of taken non-freeable space. */
        uint32_t         taken;
    } u;

    /*
     * Size of chunks or page shifted by pool->chunk_size_shift.  Zero means
     * that page is free, 0xFF means page with non-freeable allocations.
     */
    uint8_t              size;

    /* Number of free chunks of a chunked page. */
    uint8_t              chunks;

    /*
     * Number of allocation fails due to free space insufficiency
     * in non-freeable page.
     */
    uint8_t              fails;

    /*
     * Page number in page cluster.
     * There can be no more than 256 pages in a cluster.
     */
    uint8_t              number;
} ngx_mp_page_t;


/*
 * Some malloc implementations (e.g. jemalloc) allocates large enough
 * blocks (e.g. greater than 4K) with 4K alignment.  So if a block
 * descriptor will be allocated together with the block it will take
 * excessive 4K memory.  So it is better to allocate the block descriptor
 * apart.
 */

typedef enum {
    /* Block of cluster.  The block is allocated apart of the cluster. */
    NGX_MP_CLUSTER_BLOCK = 0,
    /*
     * Block of large allocation.
     * The block is allocated apart of the allocation.
     */
    NGX_MP_DISCRETE_BLOCK,
    /*
     * Block of large allocation.
     * The block is allocated just after of the allocation.
     */
    NGX_MP_EMBEDDED_BLOCK,
} ngx_mp_block_type_t;


typedef struct {
    NXT_RBTREE_NODE      (node);
    ngx_mp_block_type_t  type:8;
    uint8_t              freeable;

    /* Block size must be less than 4G. */
    uint32_t             size;

    u_char               *start;
    ngx_mp_page_t        pages[];
} ngx_mp_block_t;


struct ngx_mp_s {
    /* rbtree of ngx_mp_block_t. */
    nxt_rbtree_t         blocks;

    uint8_t              chunk_size_shift;
    uint8_t              page_size_shift;
    uint32_t             page_size;
    uint32_t             page_alignment;
    uint32_t             cluster_size;
    uint32_t             retain;

    /* Lists of ngx_mp_page_t. */
    nxt_queue_t          free_pages;
    nxt_queue_t          nget_pages;
    nxt_queue_t          get_pages;
    nxt_queue_t          chunk_pages[];
};


#define ngx_mp_chunk_get_free(map)                                            \
    (__builtin_ffs(map) - 1)


#define ngx_mp_chunk_is_free(map, chunk)                                      \
    ((map & (1 << chunk)) != 0)


#define ngx_mp_chunk_set_busy(map, chunk)                                     \
    map &= ~(1 << chunk)


#define ngx_mp_chunk_set_free(map, chunk)                                     \
    map |= (1 << chunk)


#define ngx_mp_free_junk(p, size)                                             \
    memset((p), 0x5A, size)


static void *ngx_mp_alloc_small(ngx_mp_t *mp, size_t size);
static void *ngx_mp_get_small(ngx_mp_t *mp, nxt_queue_t *pages, size_t size);
static ngx_mp_page_t *ngx_mp_alloc_page(ngx_mp_t *mp);
static ngx_mp_block_t *ngx_mp_alloc_cluster(ngx_mp_t *mp);
static void *ngx_mp_alloc_large(ngx_mp_t *mp, size_t alignment, size_t size,
    ngx_flag_t freeable);
static intptr_t ngx_mp_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static ngx_mp_block_t *ngx_mp_find_block(nxt_rbtree_t *tree, u_char *p);
static const char *ngx_mp_chunk_free(ngx_mp_t *mp, ngx_mp_block_t *cluster,
    u_char *p);


#define ngx_lg2(value)                                                        \
    (31 - __builtin_clz(value))


ngx_mp_t *
ngx_mp_create(size_t cluster_size, size_t page_alignment, size_t page_size,
    size_t min_chunk_size)
{
    ngx_mp_t     *mp;
    uint32_t     pages, chunk_size_shift, page_size_shift;
    nxt_queue_t  *chunk_pages;

    chunk_size_shift = ngx_lg2(min_chunk_size);
    page_size_shift = ngx_lg2(page_size);

    pages = page_size_shift - chunk_size_shift;

    mp = nxt_zalloc(sizeof(ngx_mp_t) + pages * sizeof(nxt_queue_t));

    if (mp != NULL) {
        mp->retain = 1;
        mp->chunk_size_shift = chunk_size_shift;
        mp->page_size_shift = page_size_shift;
        mp->page_size = page_size;
        mp->page_alignment = nxt_max(page_alignment, NXT_MAX_ALIGNMENT);
        mp->cluster_size = cluster_size;

        chunk_pages = mp->chunk_pages;

        while (pages != 0) {
            nxt_queue_init(chunk_pages);
            chunk_pages++;
            pages--;
        }

        nxt_queue_init(&mp->free_pages);
        nxt_queue_init(&mp->nget_pages);
        nxt_queue_init(&mp->get_pages);

        nxt_rbtree_init(&mp->blocks, ngx_mp_rbtree_compare);
    }

    return mp;
}


void
ngx_mp_destroy(ngx_mp_t *mp)
{
    void               *p;
    ngx_mp_block_t     *block;
    nxt_rbtree_node_t  *node, *next;

    next = nxt_rbtree_root(&mp->blocks);

    while (next != nxt_rbtree_sentinel(&mp->blocks)) {

        node = nxt_rbtree_destroy_next(&mp->blocks, &next);
        block = (ngx_mp_block_t *) node;

        p = block->start;

        if (block->type != NGX_MP_EMBEDDED_BLOCK) {
            nxt_free(block);
        }

        nxt_free(p);
    }

    nxt_free(mp);
}


ngx_flag_t
ngx_mp_is_empty(ngx_mp_t *mp)
{
    return (nxt_rbtree_is_empty(&mp->blocks)
            && nxt_queue_is_empty(&mp->free_pages));
}


void *
ngx_mp_alloc(ngx_mp_t *mp, size_t size)
{
    void  *p;

    if (size <= mp->page_size) {
        p = ngx_mp_alloc_small(mp, size);

    } else {
        p = ngx_mp_alloc_large(mp, NXT_MAX_ALIGNMENT, size, 1);
    }

    return p;
}


void *
ngx_mp_zalloc(ngx_mp_t *mp, size_t size)
{
    void  *p;

    p = ngx_mp_alloc(mp, size);

    if (p != NULL) {
        memset(p, 0, size);
    }

    return p;
}


void *
ngx_mp_align(ngx_mp_t *mp, size_t alignment, size_t size)
{
    void    *p;
    size_t  aligned_size;

    /* Alignment must be a power of 2. */

    if (nxt_is_power_of_two(alignment)) {

        aligned_size = nxt_max(size, alignment);

        if (aligned_size <= mp->page_size && alignment <= mp->page_alignment) {
            p = ngx_mp_alloc_small(mp, aligned_size);

        } else {
            p = ngx_mp_alloc_large(mp, alignment, size, 1);
        }

    } else {
        p = NULL;
    }

    return p;
}


void *
ngx_mp_zalign(ngx_mp_t *mp, size_t alignment, size_t size)
{
    void  *p;

    p = ngx_mp_align(mp, alignment, size);

    if (p != NULL) {
        memset(p, 0, size);
    }

    return p;
}


nxt_inline ngx_uint_t
ngx_mp_chunk_pages_index(ngx_mp_t *mp, size_t size)
{
    ngx_int_t  n, index;

    index = 0;

    if (size > 1) {
        n = ngx_lg2(size - 1) + 1 - mp->chunk_size_shift;

        if (n > 0) {
            index = n;
        }
    }

    return index;
}


nxt_inline u_char *
ngx_mp_page_addr(ngx_mp_t *mp, ngx_mp_page_t *page)
{
    size_t          page_offset;
    ngx_mp_block_t  *block;

    page_offset = page->number * sizeof(ngx_mp_page_t)
                  + offsetof(ngx_mp_block_t, pages);

    block = (ngx_mp_block_t *) ((u_char *) page - page_offset);

    return block->start + (page->number << mp->page_size_shift);
}


static void *
ngx_mp_alloc_small(ngx_mp_t *mp, size_t size)
{
    u_char            *p;
    ngx_uint_t        n, index;
    nxt_queue_t       *chunk_pages;
    ngx_mp_page_t     *page;
    nxt_queue_link_t  *link;

    p = NULL;

    if (size <= mp->page_size / 2) {

        index = ngx_mp_chunk_pages_index(mp, size);
        chunk_pages = &mp->chunk_pages[index];

        if (!nxt_queue_is_empty(chunk_pages)) {

            link = nxt_queue_first(chunk_pages);
            page = nxt_queue_link_data(link, ngx_mp_page_t, link);

            p = ngx_mp_page_addr(mp, page);

            n = ngx_mp_chunk_get_free(page->u.map);
            ngx_mp_chunk_set_busy(page->u.map, n);

            p += ((n << index) << mp->chunk_size_shift);

            page->chunks--;

            if (page->chunks == 0) {
                /*
                 * Remove full page from the pool chunk pages list
                 * of pages with free chunks.
                 */
                nxt_queue_remove(&page->link);
            }

        } else {
            page = ngx_mp_alloc_page(mp);

            if (page != NULL) {
                page->size = (1 << index);

                n = mp->page_size_shift - (index + mp->chunk_size_shift);
                page->chunks = (1 << n) - 1;

                nxt_queue_insert_head(chunk_pages, &page->link);

                /* Mark the first chunk as busy. */
                page->u.map = 0xFFFFFFFE;

                p = ngx_mp_page_addr(mp, page);
            }
        }

    } else {
        page = ngx_mp_alloc_page(mp);

        if (page != NULL) {
            page->size = mp->page_size >> mp->chunk_size_shift;

            p = ngx_mp_page_addr(mp, page);
        }
    }

    return p;
}


static void *
ngx_mp_get_small(ngx_mp_t *mp, nxt_queue_t *pages, size_t size)
{
    u_char            *p;
    uint32_t          available;
    ngx_mp_page_t     *page;
    nxt_queue_link_t  *link, *next;

    for (link = nxt_queue_first(pages);
         link != nxt_queue_tail(pages);
         link = next)
    {
        next = nxt_queue_next(link);
        page = nxt_queue_link_data(link, ngx_mp_page_t, link);

        available = mp->page_size - page->u.taken;

        if (size <= available) {
            goto found;
        }

        if (available == 0 || page->fails++ > 100) {
            nxt_queue_remove(link);
        }
    }

    page = ngx_mp_alloc_page(mp);

    if (page == NULL) {
        return page;
    }

    nxt_queue_insert_head(pages, &page->link);

    page->size = 0xFF;
    page->u.taken = 0;

found:

    p = ngx_mp_page_addr(mp, page);

    p += page->u.taken;
    page->u.taken += size;

    return p;
}


static ngx_mp_page_t *
ngx_mp_alloc_page(ngx_mp_t *mp)
{
    ngx_mp_page_t     *page;
    ngx_mp_block_t    *cluster;
    nxt_queue_link_t  *link;

    if (nxt_queue_is_empty(&mp->free_pages)) {
        cluster = ngx_mp_alloc_cluster(mp);
        if (cluster == NULL) {
            return NULL;
        }
    }

    link = nxt_queue_first(&mp->free_pages);
    nxt_queue_remove(link);

    page = nxt_queue_link_data(link, ngx_mp_page_t, link);

    return page;
}


static ngx_mp_block_t *
ngx_mp_alloc_cluster(ngx_mp_t *mp)
{
    ngx_uint_t      n;
    ngx_mp_block_t  *cluster;

    n = mp->cluster_size >> mp->page_size_shift;

    cluster = nxt_zalloc(sizeof(ngx_mp_block_t) + n * sizeof(ngx_mp_page_t));

    if (cluster == NULL) {
        return NULL;
    }

    /* NXT_MP_CLUSTER_BLOCK type is zero. */

    cluster->size = mp->cluster_size;

    cluster->start = nxt_memalign(mp->page_alignment, mp->cluster_size);
    if (cluster->start == NULL) {
        nxt_free(cluster);
        return NULL;
    }

    n--;
    cluster->pages[n].number = n;
    nxt_queue_insert_head(&mp->free_pages, &cluster->pages[n].link);

    while (n != 0) {
        n--;
        cluster->pages[n].number = n;
        nxt_queue_insert_before(&cluster->pages[n + 1].link,
                                &cluster->pages[n].link);
    }

    nxt_rbtree_insert(&mp->blocks, &cluster->node);

    return cluster;
}


static void *
ngx_mp_alloc_large(ngx_mp_t *mp, size_t alignment, size_t size,
    ngx_flag_t freeable)
{
    u_char          *p;
    size_t          aligned_size;
    uint8_t         type;
    ngx_mp_block_t  *block;

    /* Allocation must be less than 4G. */
    if (size >= 0xFFFFFFFF) {
        return NULL;
    }

    if (nxt_is_power_of_two(size)) {
        block = nxt_malloc(sizeof(ngx_mp_block_t));
        if (block == NULL) {
            return NULL;
        }

        p = nxt_memalign(alignment, size);
        if (p == NULL) {
            nxt_free(block);
            return NULL;
        }

        type = NGX_MP_DISCRETE_BLOCK;

    } else {
        aligned_size = nxt_align_size(size, sizeof(uintptr_t));

        p = nxt_memalign(alignment, aligned_size + sizeof(ngx_mp_block_t));
        if (p == NULL) {
            return NULL;
        }

        block = (ngx_mp_block_t *) (p + aligned_size);
        type = NGX_MP_EMBEDDED_BLOCK;
    }

    block->type = type;
    block->freeable = freeable;
    block->size = size;
    block->start = p;

    nxt_rbtree_insert(&mp->blocks, &block->node);

    return p;
}


static intptr_t
ngx_mp_rbtree_compare(nxt_rbtree_node_t *node1, nxt_rbtree_node_t *node2)
{
    ngx_mp_block_t  *block1, *block2;

    block1 = (ngx_mp_block_t *) node1;
    block2 = (ngx_mp_block_t *) node2;

    /*
     * Shifting is necessary to prevent overflow of intptr_t when block1->start
     * is much greater than block2->start or vice versa.
     *
     * It is safe to drop one bit since there cannot be adjacent addresses
     * because of alignments and allocation sizes.  Effectively this reduces
     * the absolute values to fit into the magnitude of intptr_t.
     */
    return ((uintptr_t) block1->start >> 1) - ((uintptr_t) block2->start >> 1);
}


void
ngx_mp_free(ngx_mp_t *mp, void *p)
{
    const char      *err;
    ngx_mp_block_t  *block;

    block = ngx_mp_find_block(&mp->blocks, p);

    if (block != NULL) {

        if (block->type == NGX_MP_CLUSTER_BLOCK) {
            err = ngx_mp_chunk_free(mp, block, p);

            if (err == NULL) {
                return;
            }

        } else if (p == block->start) {

            if (block->freeable) {
                nxt_rbtree_delete(&mp->blocks, &block->node);

                if (block->type == NGX_MP_DISCRETE_BLOCK) {
                    nxt_free(block);
                }

                nxt_free(p);

                return;
            }

            err = "freed pointer points to non-freeable block: %p";

        } else {
            err = "freed pointer points to middle of block: %p";
        }

    } else {
        err = "freed pointer is out of pool: %p";
    }
}


static ngx_mp_block_t *
ngx_mp_find_block(nxt_rbtree_t *tree, u_char *p)
{
    ngx_mp_block_t     *block;
    nxt_rbtree_node_t  *node, *sentinel;

    node = nxt_rbtree_root(tree);
    sentinel = nxt_rbtree_sentinel(tree);

    while (node != sentinel) {

        block = (ngx_mp_block_t *) node;

        if (p < block->start) {
            node = node->left;

        } else if (p >= block->start + block->size) {
            node = node->right;

        } else {
            return block;
        }
    }

    return NULL;
}


static const char *
ngx_mp_chunk_free(ngx_mp_t *mp, ngx_mp_block_t *cluster, u_char *p)
{
    u_char         *start;
    uintptr_t      offset;
    ngx_uint_t     n, size, chunk;
    nxt_queue_t    *chunk_pages;
    ngx_mp_page_t  *page;

    n = (p - cluster->start) >> mp->page_size_shift;
    start = cluster->start + (n << mp->page_size_shift);

    page = &cluster->pages[n];

    if (page->size == 0) {
        return "freed pointer points to already free page: %p";
    }

    if (page->size == 0xFF) {
        return "freed pointer points to non-freeable page: %p";
    }

    size = page->size << mp->chunk_size_shift;

    if (size != mp->page_size) {

        offset = (uintptr_t) (p - start) & (mp->page_size - 1);
        chunk = offset / size;

        if (offset != chunk * size) {
            return "freed pointer points to wrong chunk: %p";
        }

        if (ngx_mp_chunk_is_free(page->u.map, chunk)) {
            return "freed pointer points to already free chunk: %p";
        }

        ngx_mp_chunk_set_free(page->u.map, chunk);

        if (page->u.map != 0xFFFFFFFF) {
            page->chunks++;

            if (page->chunks == 1) {
                /*
                 * Add the page to the head of pool chunk pages list
                 * of pages with free chunks.
                 */
                n = ngx_mp_chunk_pages_index(mp, size);
                chunk_pages = &mp->chunk_pages[n];

                nxt_queue_insert_head(chunk_pages, &page->link);
            }

            ngx_mp_free_junk(p, size);

            return NULL;

        } else {
            /*
             * All chunks are free, remove the page from pool
             * chunk pages list of pages with free chunks.
             */
            nxt_queue_remove(&page->link);
        }

    } else if (p != start) {
        return "invalid pointer to chunk: %p";
    }

    /* Add the free page to the pool's free pages tree. */

    page->size = 0;
    nxt_queue_insert_head(&mp->free_pages, &page->link);

    ngx_mp_free_junk(p, size);

    /* Test if all pages in the cluster are free. */

    n = mp->cluster_size >> mp->page_size_shift;
    page = cluster->pages;

    do {
         if (page->size != 0) {
             return NULL;
         }

         page++;
         n--;
    } while (n != 0);

    /* Free cluster. */

    n = mp->cluster_size >> mp->page_size_shift;
    page = cluster->pages;

    do {
         nxt_queue_remove(&page->link);
         page++;
         n--;
    } while (n != 0);

    nxt_rbtree_delete(&mp->blocks, &cluster->node);

    p = cluster->start;

    nxt_free(cluster);
    nxt_free(p);

    return NULL;
}


void *
ngx_mp_nget(ngx_mp_t *mp, size_t size)
{
    void  *p;

    if (size <= mp->page_size) {
        p = ngx_mp_get_small(mp, &mp->nget_pages, size);

    } else {
        p = ngx_mp_alloc_large(mp, NXT_MAX_ALIGNMENT, size, 0);
    }

    return p;
}


void *
ngx_mp_get(ngx_mp_t *mp, size_t size)
{
    void  *p;

    if (size <= mp->page_size) {
        size = nxt_max(size, NXT_MAX_ALIGNMENT);
        p = ngx_mp_get_small(mp, &mp->get_pages, size);

    } else {
        p = ngx_mp_alloc_large(mp, NXT_MAX_ALIGNMENT, size, 0);
    }

    return p;
}


void *
ngx_mp_zget(ngx_mp_t *mp, size_t size)
{
    void  *p;

    p = ngx_mp_get(mp, size);

    if (p != NULL) {
        memset(p, 0, size);
    }

    return p;
}
