#ifndef CREATEOVAL_H
#define CREATEOVAL_H

#include "ForwardDecls.h"

#include <QDialog>

extern "C"
{
#include <xccdf_benchmark.h>
}

#include "ui_CreateOval.h"

class CreateOval : public QDialog
{
    Q_OBJECT

public:
    explicit CreateOval(QWidget *parent = 0);
    virtual ~CreateOval();

private:
    Ui_CreateOval mUI;

private slots:
    void on_Ok_clicked();
    void on_Cancel_clicked();
};

extern CreateOval* globalCreateOval;

#endif // CREATEOVAL_H
