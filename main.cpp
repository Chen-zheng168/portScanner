#include <QApplication>
#include "Gui.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Gui g;
    g.show();

    return a.exec();
}