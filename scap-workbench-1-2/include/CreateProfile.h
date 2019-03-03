#ifndef SCAP_WORKBENCH_CREATE_PROFILE_H
#define SCAP_WORKBENCH_CREATE_PROFILE_H

#include "ForwardDecls.h"

#include <QDialog>

extern "C"
{
#include <xccdf_benchmark.h>
}

#include "ui_CreateProfile.h"

class CreateProfile : public QDialog
{
    Q_OBJECT

public:
    explicit CreateProfile(QWidget *parent = 0);
    virtual ~CreateProfile();

private:
    Ui_CreateProfile mUI;

private slots:
    void on_Ok_clicked();
    void on_Cancel_clicked();
};

extern CreateProfile* globalCreateProfile;

#endif // SCAP_WORKBENCH_CREATE_PROFILE_H
