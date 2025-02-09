import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.svm import LinearSVC
from ucimlrepo import fetch_ucirepo
from sklearn.decomposition import PCA
from prettytable import PrettyTable
from sklearn.naive_bayes import BernoulliNB
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

##########################################
# Funciones preprocesamiento del dataset #
##########################################

def cargar_datos():
    phishing_websites = fetch_ucirepo(id=327)
    x = phishing_websites.data.features
    y = phishing_websites.data.targets
    return x, y


def analisisPCA(data, explained_pca_ratio=0.90):
    scaler = StandardScaler(with_mean=True, with_std=True)
    data_scaled = scaler.fit_transform(data)
    pca = PCA().fit(data_scaled)
    line_data = np.cumsum(pca.explained_variance_ratio_)
    line_data = np.insert(line_data, 0, 0)
    plt.bar(np.arange(1, len(pca.explained_variance_ratio_) + 1), pca.explained_variance_ratio_, color='g')
    plt.plot(np.arange(0, len(line_data)), line_data, marker='D')
    plt.xlim(0, len(pca.explained_variance_ratio_))
    plt.axhline(y=explained_pca_ratio, color='black', linestyle='--')
    plt.xlabel('Número de componentes')
    plt.ylabel('Varianza total')
    plt.title('Análisis PCA - Varianza explicada')
    plt.show()
    pca_sk = PCA(n_components=explained_pca_ratio)
    data_pca = pca_sk.fit_transform(data_scaled)

    return data_pca, pca_sk, scaler


def dibujarMatrizCorrelacion(data):
    corr = data.corr()
    plt.figure(figsize=(10, 8))
    sns.heatmap(corr, annot=True, cmap="coolwarm", fmt=".2f", cbar=True)
    plt.title("Matriz de Correlación")
    plt.show()


def preparar_datos(x, y, test_size=0.3, random_state=219):
    x_train, x_test, y_train, y_test = train_test_split(
        x, y.values.ravel(), test_size=test_size, random_state=random_state, stratify=y
    )

    return x_train, x_test, y_train, y_test


def randomForest():
    print("Algoritmo seleccionado: Random Forest.\n")
    return RandomForestClassifier(n_estimators = 100, criterion = "gini", max_features = 'log2',  random_state = 0)


def xgboost():
    print("Algoritmo seleccionado: HistGradientBoostingClassifier.\n")
    return HistGradientBoostingClassifier(loss='log_loss', learning_rate=0.1, max_iter=100, max_leaf_nodes=31, random_state=42)


def naiveBayes():
    print("Algoritmo seleccionado: Naive Bayes.\n")
    return BernoulliNB(alpha=1.0, binarize=0.0, fit_prior=True)


def knn():
    print("Algoritmo seleccionado: K-Nearest Neighbors (KNN).\n")
    return KNeighborsClassifier(n_neighbors=30, algorithm='kd_tree', leaf_size=30, metric='minkowski', p=2, weights='distance')


def svm():
    print("Algoritmo seleccionado: Support Vector Classification (SVC).\n")
    return LinearSVC(C=2.0, dual=False, loss='squared_hinge', penalty='l2', random_state=None, tol=0.0001)


def train(algorithm, x_train, y_train):
    algorithm.fit(x_train, y_train)
    return algorithm


def test(algorithm, x_test, y_test):
    y_test_pred = algorithm.predict(x_test)
    precision = precision_score(y_test, y_test_pred, average='weighted')
    recall = recall_score(y_test, y_test_pred, average='weighted')
    f1 = f1_score(y_test, y_test_pred, average='weighted')
    print(f"Precisión (Precision): {precision:.10f}")
    print(f"Sensibilidad (Recall): {recall:.10f}")
    print(f"Puntaje F1 (F1-score): {f1:.10f}")
    cm = confusion_matrix(y_test, y_test_pred)
    conf_matrix_list = np.ndarray.tolist(cm)
    table = PrettyTable()
    table.field_names = ["", "Predicción negativa", "Predicción positiva"]
    table.add_row(["Real negativa", conf_matrix_list[0][0], conf_matrix_list[0][1]])
    table.add_row(["Real positiva", conf_matrix_list[1][0], conf_matrix_list[1][1]])
    print("Confusion Matrix:")
    print(table)

    return algorithm


def principal_program():

    print("Cargando datos...")
    x, y = cargar_datos()
    print("Datos cargados.\n")

    print("Dibujando matriz de correlación...")
    dibujarMatrizCorrelacion(x)
    print("Matriz de correlación dibujada.\n")

    print("Aplicando PCA a los datos...")
    x, pca, scaler = analisisPCA(x)
    print("PCA aplicado.\n")

    print("Dividiendo dataset...")
    x_train, x_test, y_train, y_test = preparar_datos(x, y)
    print('\tDataset original: ', x.shape, y.shape)
    print('\tEntrenamiento: ', x_train.shape, y_train.shape)
    print('\tTest: ', x_test.shape, y_test.shape)
    print("Dataset dividido.\n")

    print("Seleccionando algoritmo...")
    #algorithm = naiveBayes()
    #algorithm = knn()
    #algorithm = svm()
    #algorithm = randomForest()
    algorithm = xgboost()

    print("Entrenando modelo...")
    algorithm = train(algorithm, x_train, y_train)
    print("Modelo entrenado.\n")

    print("Probando modelo...:")
    algorithm = test(algorithm, x_test, y_test)
    print("Modelo probado.\n")

    return algorithm, pca, scaler


if __name__ == '__main__':
    principal_program()
