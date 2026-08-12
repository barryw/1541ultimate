#ifndef TREEBROWSER_STATE_H
#define TREEBROWSER_STATE_H

#include "userinterface.h"
#include "browsable.h"

class TreeBrowser;

class TreeBrowserState
{
public:
	int level;
	TreeBrowser *browser; // owner

	int cursor_pos;
	Browsable *under_cursor; // on cursor

	int first_item_on_screen;
    int selected_line; // y-cursor

    int initial_index;
    bool refresh;
    bool needs_reload;

    // Ownership, which differs per pointer and is easy to get wrong:
    //   node      borrowed. Usually a long-lived Browsable owned elsewhere, so
    //             this class only ever kills its children, never the node. A
    //             caller that builds a node per screen owns it and must
    //             outlive the state -- see AssemblySearchForm.
    //   previous  owned. The destructor deletes the whole chain upwards.
    //   deeper    borrowed. level_up() deletes itself and clears this in the
    //             parent, and a browser torn down while nested is destroyed
    //             from its deepest state, so this is never the owning end.
    //   children  borrowed. Points into the list some Browsable returned from
    //             getSubItems(), or at the shared empty list.
    Browsable *node;
    TreeBrowserState *previous;
    TreeBrowserState *deeper;
    IndexedList<Browsable *> *children;

    // Member functions
    TreeBrowserState(Browsable *node, TreeBrowser *b, int lev);
    virtual ~TreeBrowserState();
    virtual void cleanup();

    virtual void do_refresh();
    virtual void update_selected();
    virtual void draw();
    virtual void draw_item(Browsable *t, int line, bool selected);

    //    virtual void reselect();
    virtual void reload(void);
    virtual void up(int);
    virtual void down(int);
    virtual void move_to_index(int);

    virtual void into(void);
	virtual bool into2(void);
    virtual void into3(const char* name);
    virtual void level_up(void);
    virtual void select_one(void);
    virtual void select_all(bool);

    // functions only used for config menu state
    virtual void change(void) { }
    virtual void increase(void) { }
    virtual void decrease(void) { }
};

#endif
