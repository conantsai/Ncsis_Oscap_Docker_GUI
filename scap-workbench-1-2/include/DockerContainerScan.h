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

private slots:
    void on_pushButton_cexit_clicked();

    void on_pushButton_cscan_clicked();

    void on_comboBox_cmethod_currentIndexChanged();

    void on_comboBox_cssg_currentIndexChanged();


private:
    Ui::DockerContainerScan *ui;
};

#endif // DOCKERCONTAINERSCAN_H
