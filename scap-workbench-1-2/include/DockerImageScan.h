#ifndef DOCKERIMAGESCAN_H
#define DOCKERIMAGESCAN_H

#include <QWidget>

namespace Ui {
class DockerImageScan;
}

class DockerImageScan : public QWidget
{
    Q_OBJECT

public:
    explicit DockerImageScan(QWidget *parent = 0);
    ~DockerImageScan();

private slots:
    void on_pushButton_iscan_clicked();

    void on_pushButton_iexit_clicked();

    void on_comboBox_imethod_currentIndexChanged();

    void on_comboBox_issg_currentIndexChanged();

private:
    Ui::DockerImageScan *ui;
};

#endif // DOCKERIMAGESCAN_H
