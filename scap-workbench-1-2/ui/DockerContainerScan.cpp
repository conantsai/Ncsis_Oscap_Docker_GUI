#include "DockerContainerScan.h"
#include "ui_DockerContainerScan.h"

DockerContainerScan::DockerContainerScan(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DockerContainerScan)
{
    ui->setupUi(this);
}

DockerContainerScan::~DockerContainerScan()
{
    delete ui;
}
