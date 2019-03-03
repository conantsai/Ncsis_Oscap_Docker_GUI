#ifndef CREATERULE_H
#define CREATERULE_H

#include "ForwardDecls.h"

#include <QDialog>

extern "C"
{
#include <xccdf_benchmark.h>
}

#include "ui_CreateRule.h"

class CreateRule : public QDialog
{
    Q_OBJECT

public:
    explicit CreateRule(QWidget *parent = 0);
    virtual ~CreateRule();

private:
    Ui_CreateRule mUI;

private slots:
    void on_Ok_clicked();
    void on_Cancel_clicked();
};

extern CreateRule* globalCreateRule;

#endif // CREATERULE_H
