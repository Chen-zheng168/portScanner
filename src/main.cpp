#include <QApplication>
#include "../include/Gui.h"

int main(int argc, char *argv[])
{
    qRegisterMetaType<uint16_t>("uint16_t");
    QApplication a(argc, argv);
    Gui g;
    g.show();

    return a.exec();
}