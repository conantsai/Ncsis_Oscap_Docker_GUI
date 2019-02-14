#ifndef DOCKERCONTAINERSCAN_H
#define DOCKERCONTAINERSCAN_H

#include <QWidget>

namespace Ui {
class DockerContainerScan;
}

class DockerContainerScan : public QWidget
{
    Q_OBJECT

public:
    explicit DockerContainerScan(QWidget *parent = 0);
    ~DockerContainerScan();

private:
    Ui::DockerContainerScan *ui;
};

#endif // DOCKERCONTAINERSCAN_H
