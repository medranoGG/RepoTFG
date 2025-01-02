import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import seaborn as sns
from time import sleep
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import BernoulliNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC, SVC
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler


def cargar_datos():
    phishing_websites = fetch_ucirepo(id=327)
    x = phishing_websites.data.features
    y = phishing_websites.data.targets
    return x, y


def eliminarFilasConVacios(data, limite=15):
    filas_antes = data.shape[0]
    # Aplicar la eliminación de filas
    data_limpio = data.dropna(thresh=len(data.columns) - limite)
    # Número de filas después de eliminar
    filas_despues = data_limpio.shape[0]
    # Calcular y mostrar el número de filas eliminadas
    filas_eliminadas = filas_antes - filas_despues
    print(f"Número de filas eliminadas: {filas_eliminadas}")

    return data_limpio
    #return data.dropna(thresh=len(data.columns) - limite)


def rellenarConModa(data):
    total_rellenados = 0
    for column in data.columns:
        # Contar valores nulos antes del relleno
        nulos_antes = data[column].isnull().sum()

        # Calcular la moda
        if nulos_antes > 0:  # Evitar operaciones innecesarias si no hay nulos
            moda = data[column].mode()[0]
            data[column] = data[column].fillna(moda)

            # Actualizar el total de valores rellenados
            total_rellenados += nulos_antes

    print(f"Total de valores nulos rellenados: {total_rellenados}")
    return data


def eliminarColumnasRedundantes(data, limite=0.75):
    corr_matrix = data.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [column for column in upper.columns if any(upper[column] > limite)]
    if to_drop:
        print(f"Columnas eliminadas: {', '.join(to_drop)}")
    else:
        print("No se eliminaron columnas redundantes.")
    return data.drop(columns=to_drop, axis=1)



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
    #return RandomForestClassifier(criterion='entropy', max_depth=15, max_features='sqrt', n_estimators=200, min_samples_split=10, min_samples_leaf=5)
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
    #return SVC(C=1000, kernel = 'rbf', gamma = 0.2 , random_state = 0)




def train(algorithm, x_train, y_train):
    algorithm.fit(x_train, y_train)
    y_train_pred = algorithm.predict(x_train)
    train_accuracy = accuracy_score(y_train, y_train_pred)
    precision = precision_score(y_train, y_train_pred, average='weighted')
    recall = recall_score(y_train, y_train_pred, average='weighted')
    f1 = f1_score(y_train, y_train_pred, average='weighted')
    print(f"Precisión (Accuracy): {train_accuracy:.10f}")
    print(f"Precisión (Precision): {precision:.10f}")
    print(f"Sensibilidad (Recall): {recall:.10f}")
    print(f"Puntaje F1 (F1-score): {f1:.10f}")
    return algorithm


def test(algorithm, x_test, y_test):
    y_test_pred = algorithm.predict(x_test)
    test_accuracy = accuracy_score(y_test, y_test_pred)
    precision = precision_score(y_test, y_test_pred, average='weighted')
    recall = recall_score(y_test, y_test_pred, average='weighted')
    f1 = f1_score(y_test, y_test_pred, average='weighted')
    print(f"Precisión (Accuracy): {test_accuracy:.10f}")
    print(f"Precisión (Precision): {precision:.10f}")
    print(f"Sensibilidad (Recall): {recall:.10f}")
    print(f"Puntaje F1 (F1-score): {f1:.10f}")

    return algorithm


def analisisPCA(data, explained_pca_ratio=0.90):
    # Escalar los datos usando StandardScaler
    scaler = StandardScaler(with_mean=True, with_std=True) # Normalización o Estandarización. Le paso media y desviación, estoy usando estandarización o zscorescalin
    data_scaled = scaler.fit_transform(data)  # Escalamos los datos

    # Aplicar PCA
    pca = PCA().fit(data_scaled)

    # Calcular la varianza explicada acumulada
    line_data = np.cumsum(pca.explained_variance_ratio_)
    line_data = np.insert(line_data, 0, 0)

    # Graficar la varianza explicada
    plt.bar(np.arange(1, len(pca.explained_variance_ratio_) + 1), pca.explained_variance_ratio_, color='g')
    plt.plot(np.arange(0, len(line_data)), line_data, marker='D')
    plt.xlim(0, len(pca.explained_variance_ratio_))  # Solo dos argumentos
    plt.axhline(y=explained_pca_ratio, color='black', linestyle='--')
    plt.xlabel('Número de componentes')
    plt.ylabel('Varianza explicada acumulada')
    plt.title('Análisis PCA - Varianza explicada')
    plt.show()

    # Reducir dimensiones basándonos en el ratio de varianza explicada
    pca_sk = PCA(n_components=explained_pca_ratio)

    # Aplicar PCA y obtener los datos transformados
    data_pca = pca_sk.fit_transform(data_scaled)

    return data_pca, pca_sk, scaler # Devolvemos directamente el data_pca porque si andamos con dataframes da errores



def principal_program():

    print("Cargamos datos...")
    x, y = cargar_datos()
    print("Datos cargados.\n")

    print("Eliminando filas vacías...")
    x = eliminarFilasConVacios(x)
    print("Filas redundantes eliminadas.\n")

    print("Rellenando columnas con valores vacíos...")
    x = rellenarConModa(x)
    print("Columnas rellenas.\n")

    #print(x)
    #print("Eliminando columnas redundantes...")
    #x = eliminarColumnasRedundantes(x) # Tiene mas sentido hacer el PCA solo
    #columns = x.columns.tolist()
    #print("Total columnas tras eliminar:" + str(x.columns.size) + "\n")

    print("Matriz de correlación...")
    dibujarMatrizCorrelacion(x)
    print("Matriz de correlación dibujada.\n")

    print("Aplicando PCA a los datos...")
    x, pca, scaler = analisisPCA(x)
    print("PCA aplicado.\n")


    print("Preprocesamos datos...")
    x_train, x_test, y_train, y_test = preparar_datos(x, y)
    #print('Tamaños: ')
    #print('\tDataset original: ', x.shape, y.shape)
    #print('\tEntrenamiento: ', x_train.shape, y_train.shape)
    #print('\tPrueba: ', x_test.shape, y_test.shape)
    print("Datos preprocesados.\n")

    print("Seleccionamos algoritmo...")
    #algorithm = naiveBayes()  # 0.8489599035
    #algorithm = knn() # 0.9580946639
    #algorithm = svm() # 0.9231233042
    #algorithm = randomForest() # 0.9532710280
    algorithm = xgboost() # 0.9611094362

    print("Entrenando modelo...")
    algorithm = train(algorithm, x_train, y_train)
    print("Modelo entrenado.\n")

    print("Resultados:")
    algorithm = test(algorithm, x_test, y_test)
    print("\n")

    '''
    print("Predecir resultado API...:")
    # Prueba para testear una línea (api)
    url_api = [[0, -1, -1, -1, 1, -1, -1, 1, -1, 1, 0, -1, -1, 1, 1, 1, -1, -1, 1, 1, 0, 0, 1, 0, 0, 0, 1, -1, 1, 1]]
    # Crear el DataFrame con las columnas correctas
    url_api_df = pd.DataFrame(url_api)
    # Escalar los datos con el scaler entrenado
    url_api_scaled = scaler.transform(url_api_df)
    # Aplicar PCA a los datos escalados
    url_api_pca = pca.transform(url_api_scaled)
    # Hacer la predicción con el modelo entrenado
    api_pred_prob = algorithm.predict_proba(url_api_pca)
    api_pred = algorithm.predict(url_api_pca)
    # Mostrar el resultado de la predicción
    print("Predicción para URL en API:", api_pred)
    print("Predicción para URL en API %:", api_pred_prob)
    '''
    return algorithm, pca, scaler


#if __name__ == '__main__':
 #   principal_program()

