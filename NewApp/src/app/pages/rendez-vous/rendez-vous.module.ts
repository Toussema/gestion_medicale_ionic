import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { IonicModule } from '@ionic/angular';

import { RendezVousPageRoutingModule } from './rendez-vous-routing.module';

import { RendezVousPage } from './rendez-vous.page';
import { HeaderComponent } from "../../components/header/header.component";

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    IonicModule,
    RendezVousPageRoutingModule,
    HeaderComponent
],
  declarations: [RendezVousPage]
})
export class RendezVousPageModule {}
