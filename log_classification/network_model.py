import tensorflow as tf
import numpy as np
import pandas as pd
import pickle
import math
from data_preparator import prepare_data, prepare_log_row
from bo.models import NetworkParameter
from bo.network_dao import add_network_parameter

# save_path = './models/'
save_path = '../data/model/'


class SOM:
    """
    2-D Self-Organizing Map with Gaussian Neighbourhood function
    and linearly decreasing learning rate.
    """

    def __init__(self, m, n, dim, num_iterations, eta=0.5, sigma=None):
        """
        Inicializace vsech potrebnych promennych pro TF graph

        m X n je dimenze gridu site
        dim je dimenze vstupnich dat - velikost character bigramu pro jeden radek logu
        num_iterations je pocet iteraci uceni - pri kazde iteraci se projdou vsechny neurny gridu
        eta je pocatecni hodnota uciciho procesu
        sigma je pocatecni hodnota neighbourhood vzdalenosti - kolik neuronu
            od BMU je ovlivneno behem uceni
        """

        self._m = m
        self._n = n
        self._neighbourhood = []
        self._topography = []
        self._num_iterations = int(num_iterations)
        self._learned = False
        self.abnormal_dist = 0

        if sigma is None:
            sigma = max(m, n) / 2.0  # Constant radius
        else:
            sigma = float(sigma)

        # Inicializace grafu
        self._graph = tf.Graph()

        with self._graph.as_default():
            # vahy jednotlivych neuronu jsou nahodne nastavene -- matice m X n kde na kazde pozici je
            # 1-D pole velikosti dimenze vstup. dat
            self._W = tf.Variable(tf.random_normal([m * n, dim], seed=5))

            # rozlozeni gridu - pole m X n kde jsou pozice neuronu
            self._topography = tf.constant(np.array(list(self._neuron_location(m, n))))

            # Placeholder pro vstupni data
            self._X = tf.placeholder('float', [dim])

            # Placeholder pro pocet iteraci
            self._iter = tf.placeholder('float')

            # Vypocet BMU - spocita euklidovu vzdalenost mezi vstupnim vektorem a kazdym neuronem gridu (jeho vahou)
            # a vrati index index toho neuronu, ktery ma nejmensi vzdalenost
            d = tf.sqrt(tf.reduce_sum(tf.pow(self._W - tf.stack([self._X for i in range(m * n)]), 2), 1))
            self.WTU_idx = tf.argmin(d, 0)

            # vrati lokaci neuronu na zaklade jeho indexu
            slice_start = tf.pad(tf.reshape(self.WTU_idx, [1]), np.array([[0, 1]]))
            self.WTU_loc = tf.reshape(tf.slice(self._topography, slice_start, tf.constant(np.array([1, 2]))), [2])
            self.bd2 = self.WTU_loc

            # Zmena hodnot sigma a eta podle aktualni iterace
            learning_rate = 1 - self._iter / self._num_iterations
            _eta_new = eta * learning_rate
            _sigma_new = sigma * learning_rate

            # Neighbourhood funkce ktera generuje vektor s upravenou learning rate pro vsechny neurony na zaklade aktualni iterace a BMU
            distance_square = tf.reduce_sum(tf.pow(tf.subtract(self._topography, tf.stack([self.WTU_loc for i in range(m * n)])), 2), 1)
            neighbourhood_func = tf.exp(tf.negative(tf.div(tf.cast(distance_square, 'float32'), tf.pow(_sigma_new, 2))))

            # vynasobeni learning rate s fci sousedu
            # Operace je pak pouzita k aktualizaci vektoru vah jednotlivych neuronu na zaklade vstupu
            eta_into_gamma = tf.multiply(_eta_new, neighbourhood_func)

            # uprava vah na zaklade nove vypoctenych
            # nove vypoctene vahy musi byt upraveny na spravny shape
            weight_multiplier = tf.stack(
                [tf.tile(tf.slice(eta_into_gamma, np.array([i]), np.array([1])), [dim]) for i in range(m * n)])
            delta_W = tf.multiply(weight_multiplier, tf.subtract(tf.stack([self._X for i in range(m * n)]), self._W))
            new_W = self._W + delta_W
            self._training = tf.assign(self._W, new_W)

            # Inicializace vsech promennych
            init = tf.global_variables_initializer()
            self._sess = tf.Session()
            self._sess.run(init)
            self._saver = tf.train.Saver()

    def save_model(self, path):
        """
        Ulozi model do specifikovaneho adresare
        """
        save_path = self._saver.save(self._sess, path + '/model.ckp')

        attrs_to_save = {
            '_m': self._m,
            '_n': self._n,
            '_neighbourhood': self._neighbourhood,
            # '_topography': self._topography,
            '_num_iterations': self._num_iterations,
            '_Wts': self._Wts,
            '_locations': self._locations,
            '_centroid_grid': self._centroid_grid,
            '_learned': self._learned,
            'abnormal_dist': self.abnormal_dist
        }

        output = open(path + '/som.pkl', 'wb')
        pickle.dump(attrs_to_save, output)
        output.close()
        print("Model saved in path: %s" % save_path)

        pd.DataFrame(self._centroid_grid).to_csv(path + '/grid.csv', header=False, index=False)
        print('Grid saved to ' + path + ' for easy reading')

    def load_model(self, path):
        """
        Nacte model ze specifikovaneho adresare
        """
        self._saver.restore(self._sess, path + '/model.ckp')
        pkl_file = open(path + '/som.pkl', 'rb')
        restored = pickle.load(pkl_file)
        pkl_file.close()
        self._m = restored['_m']
        self._n = restored['_n']
        self._neighbourhood = restored['_neighbourhood']
        # self._topography = restored['_topography']
        self._num_iterations = restored['_num_iterations']
        self._Wts = restored['_Wts']
        self._locations = restored['_locations']
        self._learned = restored['_learned']
        self._centroid_grid = restored['_centroid_grid']
        self.abnormal_dist = restored['abnormal_dist']

        print("Model restored from path: " + path)

    def get_centroids(self):
        """
        Vrati grid site s kde na jednotlivych pozicich je pole lokaci jednotlivych centroidu
        """
        if not self._learned:
            raise ValueError("SOM not trained yet")
        return self._centroid_grid

    def fit(self, X):
        """
        Trenuje sit, Vtup musi mit stejnou dimenzi jako je dimenze pri inicializaci mapy
        Vahy neuronu jsou na zacatku nastavene nahodne
        """

        # prochazi jednotlive iterace
        for i in range(self._num_iterations):
            # trenuje kazdy neuron samostatne
            for x in X:
                self._sess.run(self._training, feed_dict={self._X: x, self._iter: i})

            # Store a centroid grid for easy retrieval later on
            centroid_grid = [[] for i in range(self._m)]
            self._Wts = list(self._sess.run(self._W))
            self._locations = list(self._sess.run(self._topography))
            for j, loc in enumerate(self._locations):
                centroid_grid[loc[0]].append(self._Wts[j])
            self._centroid_grid = centroid_grid

            self._learned = True

            if i % 10 == 0:
                print('iteration: ' + str(i) + '/' + str(self._num_iterations))

    def winner(self, x):
        """
        Vrati vitezny neuron pro dany vstup
        WTU_idx index BMU
        WTU_loc index na X a na Y osach gridu
        """
        idx = self._sess.run([self.WTU_idx, self.WTU_loc], feed_dict={self._X: x})
        return idx

    def _neuron_location(self, m, n):
        """
        Prochazi neurony site jeden po druhem a kazdy yielduje a tim vrati lokace jdnotlivejch neuronu
        Vnorene for cykly aby se vytvorili vsechny pozice neuronu v 2-D gridu site
        """
        for i in range(m):
            for j in range(n):
                yield np.array([i, j])

    def get_heatmap(self, X):
        """
        Vrati heatmapu obsahujici pocet vitezstvi pro kazdy neuron ze vstupniho datasetu. Prochazi dataset a pro kazdy log zavola winner() ktera vrati BMU.
        Vysledek mapa kde jsou neurony grid vrstvy jako klice a pocet logu z datasetu ktere maji dany neuron jako BMU jako hodnota
        """
        if not self._learned:
            raise ValueError("SOM not trained yet")

        res = {}
        for item in X:
            winner = self.winner(item)
            key = winner[0]

            if key in res:
                res[key][0] += 1
                res[key][1].append(item)
            else:
                res[key] = [1, [item], winner[1]]

        heatmap = np.zeros((self._m, self._n), dtype=np.int)
        for key, value in res.items():
            heatmap[value[2][0], value[2][1]] = int(value[0])

        return heatmap


def get_distnce(x, centroid):
    dist_sum = 0
    for i in range(len(x)):
        dist_sum += (x[i] - centroid[i]) ** 2
    return math.sqrt(dist_sum)


def compute_abnormal_distance(model, X):
    centroids = model.get_centroids()

    res_som = []
    for x in X:
        winner = model.winner(x)
        winner_loc = winner[1]
        bmu = centroids[winner_loc[0]][winner_loc[1]]
        distance = get_distnce(x, bmu)
        res_som.append((winner[0], distance))

    distance_tmp = pd.DataFrame(res_som, columns=['winner', 'distance'])
    distances_probs = []
    total_size = distance_tmp.size
    for value in range(int(distance_tmp["distance"].max() + 2)):
        dist_len = distance_tmp[distance_tmp["distance"] > value].size
        distances_probs.append((value, dist_len / total_size * 100))

    final_dist = 0
    for val in distances_probs:
        if val[1] < 3:
            final_dist = val[0]
            break

    return final_dist


def train_model(X):
    if X is None:
        raise ValueError("No data")
    n_dim = X.shape[1]
    size = 2
    model = SOM(size, size, n_dim, 1, sigma=2)
    print('SOM initialized, start training')
    model.fit(X)
    abnormal_dist = compute_abnormal_distance(model, X)
    model.abnormal_dist = abnormal_dist
    print('SOM trained')
    model.save_model(save_path + 'model_grid-' + str(size) + '.pkl')
    return model


def load_trained_model(network):
    train_data = check_if_trained(network)
    n_dim = train_data.shape[1]
    size = 2
    global model
    model = SOM(size, size, n_dim, 800, sigma=2)
    model.load_model(save_path + 'model_grid-' + str(size) + '.pkl')

    global centroids
    centroids = model.get_centroids()
    print('model loaded')
    return model


def predict(x, additional_data=None):
    winner = model.winner(x)
    winner_loc = winner[1]
    bmu = centroids[winner_loc[0]][winner_loc[1]]
    distance = get_distnce(x, bmu)
    if (distance >= model.abnormal_dist):
        return 'abnormal'
    else:
        return 'normal'


def check_if_trained(network):
    trained = False
    train_path = ""

    global pattern
    pattern = None

    for parameter in network.parameters:
        if parameter.abbreviation == "IS_TRAINED" and parameter.value is not None and parameter.value.lower() == 'true':
            trained = True

        if parameter.abbreviation == "TRAIN_DATA_PATH":
            train_path = parameter.value

        if parameter.abbreviation == "DATA_PATTERN":
            pattern = parameter.value

    train_data = prepare_data(train_path, pattern)
    if trained is False:
        train_model(train_data)
        parameter = NetworkParameter('IS_TRAINED', 'IS_TRAINED', True, network.network_id)
        add_network_parameter(parameter)
    return train_data
